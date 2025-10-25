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

async function postRaw(url, body, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}), signal: ctrl.signal });
    const t = await r.text();
    let json; try { json = t ? JSON.parse(t) : {}; } catch { json = { raw: t }; }
    return { ok: r.ok, status: r.status, json };
  } finally { clearTimeout(id); }
}

export default async function testFailureModes() {
  const h = await getJSON(`${ORCH}/health`);
  if (!h.ok) throw new Error('orchestrator not reachable');
  const { kyber, dilithium, falcon } = h.json;

  // If Kyber is unreachable, /select/ake should 502
  if (!kyber?.reachable) {
    const r = await postRaw(`${ORCH}/select/ake`, { payloadHintBytes: 512 });
    if (r.status !== 502) throw new Error(`expected 502 when Kyber down, got ${r.status}`);
    if (r.json?.error !== 'select_ake_failed') throw new Error('expected select_ake_failed error code');
    log('Properly fails when Kyber unreachable', 'green');
    return true;
  }

  // If neither signature service is reachable, selection should fail before posting to sig service
  if (!dilithium?.reachable && !falcon?.reachable) {
    const r = await postRaw(`${ORCH}/select/ake`, { payloadHintBytes: 2048 });
    if (r.status !== 502) throw new Error(`expected 502 when no sig service, got ${r.status}`);
    if (!/No signature service reachable/i.test(r.json?.detail || '')) throw new Error('expected no signature service error');
    log('Properly fails when no signature services reachable', 'green');
    return true;
  }

  return { skipped: true, reason: 'preconditions not met for failure modes' };
}
