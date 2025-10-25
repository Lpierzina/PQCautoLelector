#!/usr/bin/env node

const ORCH = process.env.ORCH_BASE || 'http://localhost:8090';

function log(m, c) {
  const colors = { green:'\x1b[32m', red:'\x1b[31m', yellow:'\x1b[33m', blue:'\x1b[34m', cyan:'\x1b[36m', bright:'\x1b[1m', reset:'\x1b[0m' };
  console.log(`${colors[c] || ''}${m}${colors.reset}`);
}

async function getJSON(url, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    const t = await r.text();
    return { ok: r.ok, status: r.status, json: t ? JSON.parse(t) : {} };
  } finally { clearTimeout(id); }
}

async function postJSON(url, body, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}), signal: ctrl.signal });
    const t = await r.text();
    return { ok: r.ok, status: r.status, json: t ? JSON.parse(t) : {} };
  } finally { clearTimeout(id); }
}

export default async function testPolicyOverrides() {
  log('Checking /health...', 'blue');
  const h = await getJSON(`${ORCH}/health`);
  if (!h.ok) throw new Error('orchestrator not reachable');
  const { kyber, dilithium, falcon } = h.json;

  if (!kyber?.reachable) {
    log('Kyber not reachable — cannot run policy override cases', 'yellow');
    return { skipped: true, reason: 'kyber unreachable' };
  }

  // Case A: tiny payload would pick Falcon, but policy prefers Dilithium
  if (dilithium?.reachable) {
    log('Policy prefers Dilithium on tiny payload — expect Dilithium', 'cyan');
    const r = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes: 256, policyPreferredSig: 'dilithium' });
    if (!r.ok) throw new Error(`/select/ake failed: ${r.json?.detail || r.status}`);
    if (r.json.schemeSelected !== 'dilithium') throw new Error(`expected dilithium, got ${r.json.schemeSelected}`);
    if (!r.json.sharedSecretMatch) throw new Error('shared secrets mismatch');
    log('Policy overrode payload heuristic to Dilithium OK', 'green');
  } else {
    log('Dilithium not reachable — skipping policy->dilithium case', 'yellow');
  }

  // Case B: large payload would pick Dilithium by default, but policy prefers Falcon
  if (falcon?.reachable) {
    log('Policy prefers Falcon on large payload — expect Falcon', 'cyan');
    const r = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes: 8192, policyPreferredSig: 'falcon' });
    if (!r.ok) throw new Error(`/select/ake failed: ${r.json?.detail || r.status}`);
    if (r.json.schemeSelected !== 'falcon') throw new Error(`expected falcon, got ${r.json.schemeSelected}`);
    if (!r.json.sharedSecretMatch) throw new Error('shared secrets mismatch');
    log('Policy overrode default to Falcon OK', 'green');
  } else {
    log('Falcon not reachable — skipping policy->falcon case', 'yellow');
  }

  return true;
}
