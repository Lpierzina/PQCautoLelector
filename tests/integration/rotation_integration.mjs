#!/usr/bin/env node

// Rotator-backed AKE flow (skips if rotator unreachable)
const ORCH = process.env.ORCH_BASE || 'http://localhost:8090';
const ROT = process.env.ROTATION_BASE || process.env.KEYROTATION_BASE || 'http://localhost:8092';

function log(m, c) {
  const colors = { green:'\x1b[32m', red:'\x1b[31m', yellow:'\x1b[33m', blue:'\x1b[34m', cyan:'\x1b[36m', bright:'\x1b[1m', reset:'\x1b[0m' };
  console.log(`${colors[c] || ''}${m}${colors.reset}`);
}

async function reachable(url) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), 1500);
  try {
    const r = await fetch(`${url}/health`, { signal: ctrl.signal });
    return !!r.ok || r.status >= 200;
  } catch { return false; } finally { clearTimeout(id); }
}

async function postJSON(url, body, timeoutMs = 6000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}), signal: ctrl.signal });
    const t = await r.text();
    return { ok: r.ok, status: r.status, json: t ? JSON.parse(t) : {} };
  } finally { clearTimeout(id); }
}

export default async function test() {
  if (!(await reachable(ROT))) {
    log('Rotation service not reachable — skipping', 'yellow');
    return { skipped: true, reason: 'rotation unreachable' };
  }

  // Ensure both algorithms have an active key
  await postJSON(`${ROT}/keys/rotate`, { alg: 'falcon-l5' });
  await postJSON(`${ROT}/keys/rotate`, { alg: 'dilithium-l3' });

  // 1) Falcon path (small payload)
  const fal = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes: 512 });
  if (!fal.ok) throw new Error(`/select/ake failed: ${fal.json?.detail || fal.status}`);
  if (!fal.json.sharedSecretMatch) throw new Error('shared secrets mismatch (falcon)');
  log(`Rotator-backed AKE OK via scheme=${fal.json.schemeSelected}`, 'green');

  // 2) Dilithium path (explicit policy)
  const dil = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes: 4096, policyPreferredSig: 'dilithium' });
  if (!dil.ok) throw new Error(`/select/ake failed: ${dil.json?.detail || dil.status}`);
  if (!dil.json.sharedSecretMatch) throw new Error('shared secrets mismatch (dilithium)');
  log(`Rotator-backed AKE OK via scheme=${dil.json.schemeSelected}`, 'green');
  return true;
}
