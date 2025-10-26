// /auto-selector/server.js
import Fastify from 'fastify';

const fastify = Fastify({ logger: true });

// ---- Config (env overrides supported) ----
const PORT = Number(process.env.PORT) || 8090;
const HOST = process.env.HOST || '0.0.0.0';

const KYBER_BASES = [
  process.env.KYBER_BASE,
  'http://localhost:8080', 'http://127.0.0.1:8080', 'http://host.docker.internal:8080'
].filter(Boolean);

const DILITHIUM_BASES = [
  process.env.DILITHIUM_BASE,
  'http://localhost:8081', 'http://127.0.0.1:8081', 'http://host.docker.internal:8081'
].filter(Boolean);

const FALCON_BASES = [
  process.env.FALCON_BASE,
  'http://localhost:8083', 'http://127.0.0.1:8083', 'http://host.docker.internal:8083'
].filter(Boolean);

// Optional: standalone PQC Key Rotation microservice
const KEYROTATION_BASES = [
  process.env.KEYROTATION_BASE || process.env.ROTATION_BASE,
  'http://localhost:8092', 'http://127.0.0.1:8092', 'http://host.docker.internal:8092'
].filter(Boolean);

// ---- helpers ----
function withTimeout(promise, ms = 2500) {
  return Promise.race([
    promise,
    new Promise((_, r) => setTimeout(() => r(new Error('timeout')), ms))
  ]);
}
async function probe(base) {
  try {
    const res = await withTimeout(fetch(`${base}/health`), 1500);
    return !!res?.ok || res?.status >= 200; // any HTTP response means reachable
  } catch (_) { return false; }
}
async function firstReachable(bases) {
  for (const b of bases) if (await probe(b)) return b;
  return null;
}
async function getJSON(url, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    const txt = await res.text();
    let json; try { json = txt ? JSON.parse(txt) : {}; } catch { json = { raw: txt }; }
    if (!res.ok) throw new Error(json?.error || `${url} -> ${res.status}`);
    return json;
  } finally { clearTimeout(id); }
}
async function postJSON(url, body, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body ?? {}),
      signal: ctrl.signal
    });
    const txt = await res.text();
    let json; try { json = txt ? JSON.parse(txt) : {}; } catch { json = { raw: txt }; }
    if (!res.ok) throw new Error(json?.error || `${url} -> ${res.status}`);
    return json;
  } finally { clearTimeout(id); }
}

// ---- policy engine ----
// Inputs: payloadHintBytes (number), policyPreferredSig ('dilithium'|'falcon'|null)
// Health-based fallback included.
async function selectSigScheme({ payloadHintBytes, policyPreferredSig }) {
  // 1) Health
  const [dReach, fReach] = await Promise.all([
    firstReachable(DILITHIUM_BASES).then(Boolean),
    firstReachable(FALCON_BASES).then(Boolean),
  ]);

  // 2) Policy preferred (if healthy)
  if (policyPreferredSig === 'falcon' && fReach) return 'falcon';
  if (policyPreferredSig === 'dilithium' && dReach) return 'dilithium';

  // 3) Payload-size heuristic (Falcon signatures are smaller)
  if (!isNaN(payloadHintBytes) && payloadHintBytes > 0) {
    if (payloadHintBytes <= 1024 && fReach) return 'falcon'; // tight channels → Falcon
  }

  // 4) Default → Dilithium if healthy, else Falcon if healthy
  if (dReach) return 'dilithium';
  if (fReach) return 'falcon';

  // 5) Neither reachable
  throw new Error('No signature service reachable');
}

// ---- endpoints ----
fastify.get('/health', async () => {
  const kb = await firstReachable(KYBER_BASES);
  const db = await firstReachable(DILITHIUM_BASES);
  const fb = await firstReachable(FALCON_BASES);
  const rb = await firstReachable(KEYROTATION_BASES);
  return {
    status: kb && (db || fb) ? 'ok' : 'degraded',
    kyber: { reachable: !!kb, base: kb },
    dilithium: { reachable: !!db, base: db },
    falcon: { reachable: !!fb, base: fb },
    rotation: { reachable: !!rb, base: rb }
  };
});

// One-call AKE: pick scheme → sign Kyber pubkey → encap/decap → return shared secret
fastify.post('/select/ake', async (req, reply) => {
  try {
    const { payloadHintBytes, policyPreferredSig, level } = req.body ?? {};
    // choose sig scheme
    const scheme = await selectSigScheme({ payloadHintBytes, policyPreferredSig });

    // discover bases
    const kyberBase = await firstReachable(KYBER_BASES);
    if (!kyberBase) throw new Error('Kyber unreachable');
    const sigBase = scheme === 'dilithium'
      ? await firstReachable(DILITHIUM_BASES)
      : await firstReachable(FALCON_BASES);
    if (!sigBase) throw new Error(`${scheme} unreachable`);

    // 1) Generate Kyber keys
    const { publicKey: kyberPublicKey, secretKey: kyberSecretKey } =
      await postJSON(`${kyberBase}/kyber/generate-keypair`, {});

    // Track the active keys that pair with the signature we will use
    let activeKyberPublicKey = kyberPublicKey;
    let activeKyberSecretKey = kyberSecretKey;

  // 2) Get orchestrator signer (from chosen scheme service)
  const signerInfo = await fetch(`${sigBase}/orchestrator/signer`).then(r => r.json());
  // Prefer algorithm-specific fields when available; fall back to generic
  const baseServiceSignerPublicKey = signerInfo.signerPublicKey
    || signerInfo.falconSignerPublicKey
    || signerInfo.dilithiumSignerPublicKey
    || signerInfo.publicKey;
  // Preserve the signature service's notion of level; we'll forward this to it
  // later when asking it to verify + encapsulate. Rotation may use a different
  // algorithm string (e.g. "falcon-l5"), but the service typically expects its
  // own level format (e.g. "Falcon-1024").
  const serviceSignerLevel = level || signerInfo.level || signerInfo.alg || signerInfo.algorithm;

  let signerPublicKey = baseServiceSignerPublicKey;
  let signerLevel = serviceSignerLevel;

  // Normalize algorithm string if embedded in level (used only for rotator alg)
  const algFromLevel = typeof serviceSignerLevel === 'string' && /^(falcon|dilithium)-l[1-5]$/i.test(serviceSignerLevel)
    ? serviceSignerLevel.toLowerCase()
    : null;

    // 3) Prefer using the Key Rotation service to sign (if available)
    //    Fallback to underlying signature service if rotation is unavailable.
    const rotationBase = await firstReachable(KEYROTATION_BASES);
    const signEndpoint = scheme === 'dilithium' ? '/dilithium/sign' : '/falcon/sign';
    let signature;
    let isCompressed;

    if (rotationBase) {
      try {
        // Choose rotation algorithm to MATCH the underlying signature service
        // Prefer explicit algorithm-style level if provided by signer
        const rotAlg = algFromLevel || (scheme === 'dilithium' ? 'dilithium-l3' : 'falcon-l5');
        // Ensure a current key exists; rotate if necessary
        let current = null;
        try {
          current = await getJSON(`${rotationBase}/orchestrator/keys/current?alg=${encodeURIComponent(rotAlg)}`);
        } catch (_) {
          // No current key — rotate to create one
          await postJSON(`${rotationBase}/keys/rotate`, { alg: rotAlg, level: signerLevel });
          current = await getJSON(`${rotationBase}/orchestrator/keys/current?alg=${encodeURIComponent(rotAlg)}`);
        }
        // Sign the Kyber public key via rotator
        const sr = await postJSON(`${rotationBase}/sign`, {
          alg: rotAlg,
          messageB64: activeKyberPublicKey
        });
        signature = sr.signatureB64 || sr.signatureBase64 || sr.signature || sr.sig;
        // Extract a usable public key from the rotator's response. Different
        // implementations may expose different field names. If we cannot find
        // one confidently, we will discard the rotation path and fall back to
        // signing directly with the signature service (ensuring alignment).
        const rotPubCandidates = [
          current?.publicKey,
          current?.publicKeyB64,
          current?.publicKeyBase64,
          current?.signerPublicKey,
          current?.falconPublicKey,
          current?.dilithiumPublicKey,
          current?.pub,
          current?.pk
        ].filter(v => typeof v === 'string' && v.length > 16);

        if (rotPubCandidates.length > 0) {
          signerPublicKey = rotPubCandidates[0];
        } else {
          // Without a clear public key from the rotator, verification would
          // fail; clear the signature so we fall back to direct signing.
          signature = undefined;
        }
        // Keep the service-provided level for downstream verification; the
        // rotator's algorithm string is not necessarily the same format.
        // Capture compression hint if rotator returns one (mainly Falcon)
        if (typeof sr.isCompressed === 'boolean') {
          isCompressed = sr.isCompressed;
        }
      } catch (_) {
        // Rotation signing failed; fall through to direct signer
      }
    }

    if (!signature) {
      try {
        // Prefer messageBase64, many services expect base64 input for signing
        const sr = await postJSON(`${sigBase}${signEndpoint}`, {
          messageBase64: activeKyberPublicKey,
          level: signerLevel
        });
        signature = sr.signature ?? sr.signatureBase64 ?? sr.sig;
        isCompressed = sr.isCompressed;
      } catch (_) {
        // Fallback to bootstrap: some services expose a bootstrap that already
        // generates a Kyber keypair and signs its public key using the internal signer.
        const b = await postJSON(`${sigBase}/orchestrator/bootstrap`, {});
        signature = b.signature ?? b.signatureBase64 ?? b.sig;
        isCompressed = b.isCompressed;

        // If bootstrap returns Kyber keys, use them to keep signature and key aligned
        if (b.kyberPublicKey && b.kyberSecretKey) {
          activeKyberPublicKey = b.kyberPublicKey;
          activeKyberSecretKey = b.kyberSecretKey;
        }
        // If bootstrap returns signer public key, prefer it
        const maybeSigner = b.signerPublicKey || b.falconSignerPublicKey || b.dilithiumSignerPublicKey || b.publicKey;
        if (maybeSigner) signerPublicKey = maybeSigner;
        if (b.level) signerLevel = b.level;
      }
    }

    if (!signature) throw new Error('No signature produced');

    // 4) Verify signature & encapsulate with verified Kyber key
    const encapRes = await postJSON(`${sigBase}/orchestrator/encapsulate-verified`, {
      kyberPublicKey: activeKyberPublicKey,
      signature,
      signerPublicKey,
      level: signerLevel,
      isCompressed
    });

    // 5) Decapsulate on Kyber to confirm shared secret
    const decapRes = await postJSON(`${kyberBase}/kyber/decapsulate`, {
      secretKey: activeKyberSecretKey,
      ciphertext: encapRes.ciphertext
    });

    const same = encapRes.sharedSecret === decapRes.sharedSecret;

    return {
      status: same ? 'ok' : 'mismatch',
      schemeSelected: scheme,
      reason: policyPreferredSig ? `policy:${policyPreferredSig}` :
              (payloadHintBytes && payloadHintBytes <= 1024) ? 'payload_tight' :
              'default_or_health',
      signerLevel,
      kyber: { ciphertextLen: encapRes.ciphertext?.length ?? 0 },
      sharedSecretMatch: same
    };
  } catch (e) {
    reply.code(502);
    return { error: 'select_ake_failed', detail: e?.message || String(e) };
  }
});

await fastify.listen({ port: PORT, host: HOST });
