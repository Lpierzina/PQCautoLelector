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

function deriveRotationAlgorithm(scheme, levelHint) {
  const defaultAlg = scheme === 'dilithium' ? 'dilithium-l3' : 'falcon-l5';

  if (typeof levelHint === 'number' && Number.isFinite(levelHint)) {
    const lvl = Math.min(5, Math.max(1, Math.round(levelHint)));
    return `${scheme}-l${lvl}`;
  }

  if (typeof levelHint === 'string') {
    const normalized = levelHint.trim().toLowerCase();
    const explicit = normalized.match(/(falcon|dilithium)[-_ ]?l?([1-5])/);
    if (explicit) return `${explicit[1]}-l${explicit[2]}`;
    const numeric = normalized.match(/([1-5])/);
    if (numeric) return `${scheme}-l${numeric[1]}`;
  }

  return defaultAlg;
}

function isSignatureVerificationError(err) {
  const msg = typeof err?.message === 'string' ? err.message.toLowerCase() : '';
  return msg.includes('signature_verification_failed')
    || msg.includes('signature verification failed')
    || msg.includes('signature mismatch')
    || msg.includes('invalid signature');
}

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
    const scheme = await selectSigScheme({ payloadHintBytes, policyPreferredSig });

    const kyberBase = await firstReachable(KYBER_BASES);
    if (!kyberBase) throw new Error('Kyber unreachable');
    const sigBase = scheme === 'dilithium'
      ? await firstReachable(DILITHIUM_BASES)
      : await firstReachable(FALCON_BASES);
    if (!sigBase) throw new Error(`${scheme} unreachable`);

    const { publicKey: initialKyberPublicKey, secretKey: initialKyberSecretKey } =
      await postJSON(`${kyberBase}/kyber/generate-keypair`, {});

    const signerInfo = await fetch(`${sigBase}/orchestrator/signer`).then(r => r.json());
    const baseServiceSignerPublicKey = signerInfo.signerPublicKey
      || signerInfo.falconSignerPublicKey
      || signerInfo.dilithiumSignerPublicKey
      || signerInfo.publicKey;
    const baseSignerLevel = level ?? signerInfo.level ?? signerInfo.alg ?? signerInfo.algorithm;
    const baseSignerKid = signerInfo.kid || signerInfo.keyId;
    const signEndpoint = scheme === 'dilithium' ? '/dilithium/sign' : '/falcon/sign';

    const rotationBase = await firstReachable(KEYROTATION_BASES);
    const rotationAlg = deriveRotationAlgorithm(scheme, baseSignerLevel);

    const signatureStrategies = [];

    if (rotationBase) {
      signatureStrategies.push(async () => {
        try {
          let current;
          try {
            current = await getJSON(`${rotationBase}/orchestrator/keys/current?alg=${encodeURIComponent(rotationAlg)}`);
          } catch (err) {
            await postJSON(`${rotationBase}/keys/rotate`, { alg: rotationAlg, level: baseSignerLevel });
            current = await getJSON(`${rotationBase}/orchestrator/keys/current?alg=${encodeURIComponent(rotationAlg)}`);
          }

          const signResp = await postJSON(`${rotationBase}/sign`, {
            alg: rotationAlg,
            level: baseSignerLevel,
            messageB64: initialKyberPublicKey,
            messageBase64: initialKyberPublicKey
          });

          const signature = signResp.signatureB64
            || signResp.signatureBase64
            || signResp.signature
            || signResp.sig;
          if (!signature) throw new Error('rotation signing produced no signature');

          const rotPubCandidates = [
            signResp.signerPublicKey,
            signResp.publicKey,
            current?.publicKey,
            current?.publicKeyB64,
            current?.publicKeyBase64,
            current?.signerPublicKey,
            current?.falconPublicKey,
            current?.dilithiumPublicKey,
            current?.pub,
            current?.pk
          ].filter(v => typeof v === 'string' && v.length > 16);

          return {
            source: 'rotation',
            signature,
            signerPublicKey: rotPubCandidates[0] || baseServiceSignerPublicKey,
            signerLevel: baseSignerLevel,
            signerKid: signResp.kid || signResp.keyId || current?.kid || current?.keyId || baseSignerKid,
            kyberPublicKey: initialKyberPublicKey,
            kyberSecretKey: initialKyberSecretKey,
            isCompressed: typeof signResp.isCompressed === 'boolean' ? signResp.isCompressed : undefined
          };
        } catch (err) {
          fastify.log.warn({ err }, 'rotation signing attempt failed');
          throw err;
        }
      });
    }

    signatureStrategies.push(async () => {
      try {
        const signResp = await postJSON(`${sigBase}${signEndpoint}`, {
          messageBase64: initialKyberPublicKey,
          messageB64: initialKyberPublicKey,
          message: initialKyberPublicKey,
          level: baseSignerLevel
        });

        const signature = signResp.signature
          || signResp.signatureBase64
          || signResp.sig
          || signResp.signatureB64;
        if (!signature) throw new Error('direct signing produced no signature');

        const signerPublicKey = signResp.signerPublicKey
          || signResp.falconSignerPublicKey
          || signResp.dilithiumSignerPublicKey
          || signResp.publicKey
          || baseServiceSignerPublicKey;

        return {
          source: 'direct',
          signature,
          signerPublicKey,
          signerLevel: signResp.level || baseSignerLevel,
          signerKid: signResp.kid || signResp.keyId || baseSignerKid,
          kyberPublicKey: initialKyberPublicKey,
          kyberSecretKey: initialKyberSecretKey,
          isCompressed: typeof signResp.isCompressed === 'boolean' ? signResp.isCompressed : undefined
        };
      } catch (err) {
        fastify.log.warn({ err }, 'direct signing attempt failed');
        throw err;
      }
    });

    signatureStrategies.push(async () => {
      const bootstrap = await postJSON(`${sigBase}/orchestrator/bootstrap`, {});
      const signature = bootstrap.signature
        || bootstrap.signatureBase64
        || bootstrap.sig
        || bootstrap.signatureB64;
      if (!signature) throw new Error('bootstrap produced no signature');

      const signerPublicKey = bootstrap.signerPublicKey
        || bootstrap.falconSignerPublicKey
        || bootstrap.dilithiumSignerPublicKey
        || bootstrap.publicKey
        || baseServiceSignerPublicKey;

      return {
        source: 'bootstrap',
        signature,
        signerPublicKey,
        signerLevel: bootstrap.level || baseSignerLevel,
        signerKid: bootstrap.kid || bootstrap.keyId || baseSignerKid,
        kyberPublicKey: bootstrap.kyberPublicKey || initialKyberPublicKey,
        kyberSecretKey: bootstrap.kyberSecretKey || initialKyberSecretKey,
        isCompressed: typeof bootstrap.isCompressed === 'boolean' ? bootstrap.isCompressed : undefined
      };
    });

    let encapRes = null;
    let ctxForDecap = null;
    let lastSigError = null;

    for (const getContext of signatureStrategies) {
      let ctx;
      try {
        ctx = await getContext();
      } catch (err) {
        continue;
      }

      if (!ctx?.signature || !ctx.signerPublicKey || !ctx.kyberPublicKey || !ctx.kyberSecretKey) {
        continue;
      }

      const payload = {
        kyberPublicKey: ctx.kyberPublicKey,
        signature: ctx.signature,
        signatureBase64: ctx.signature,
        signatureB64: ctx.signature,
        signerPublicKey: ctx.signerPublicKey,
        falconSignerPublicKey: scheme === 'falcon' ? ctx.signerPublicKey : undefined,
        dilithiumSignerPublicKey: scheme === 'dilithium' ? ctx.signerPublicKey : undefined,
        level: ctx.signerLevel ?? baseSignerLevel,
        isCompressed: ctx.isCompressed
      };

      if (ctx.signerKid) {
        payload.signerKid = ctx.signerKid;
        payload.kid = ctx.signerKid;
        payload.keyId = ctx.signerKid;
      }

      try {
        encapRes = await postJSON(`${sigBase}/orchestrator/encapsulate-verified`, payload);
        ctxForDecap = ctx;
        break;
      } catch (err) {
        if (isSignatureVerificationError(err)) {
          lastSigError = err;
          fastify.log.warn({ err, strategy: ctx.source }, 'signature verification failed, trying next strategy');
          continue;
        }
        throw err;
      }
    }

    if (!encapRes || !ctxForDecap) {
      throw lastSigError ?? new Error('No signature strategy succeeded');
    }

    const decapRes = await postJSON(`${kyberBase}/kyber/decapsulate`, {
      secretKey: ctxForDecap.kyberSecretKey,
      ciphertext: encapRes.ciphertext
    });

    const same = encapRes.sharedSecret === decapRes.sharedSecret;

    return {
      status: same ? 'ok' : 'mismatch',
      schemeSelected: scheme,
      reason: policyPreferredSig ? `policy:${policyPreferredSig}` :
              (payloadHintBytes && payloadHintBytes <= 1024) ? 'payload_tight' :
              'default_or_health',
      signerLevel: ctxForDecap.signerLevel ?? baseSignerLevel,
      signerKid: ctxForDecap.signerKid ?? baseSignerKid,
      kyber: { ciphertextLen: encapRes.ciphertext?.length ?? 0 },
      sharedSecretMatch: same
    };
  } catch (e) {
    fastify.log.error(e, 'select/ake failed');
    reply.code(502);
    return { error: 'select_ake_failed', detail: e?.message || String(e) };
  }
});
await fastify.listen({ port: PORT, host: HOST });
