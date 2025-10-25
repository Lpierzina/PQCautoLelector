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

export default async function testDefaultSelection() {
  log('Checking /health...', 'blue');
  const h = await getJSON(`${ORCH}/health`);
  if (!h.ok) throw new Error('orchestrator not reachable');
  const { kyber, dilithium, falcon } = h.json;

  if (!kyber?.reachable) {
    log('Kyber not reachable — cannot run default selection', 'yellow');
    return { skipped: true, reason: 'kyber unreachable' };
  }

  // Large payload so the payload-tight heuristic does not apply
  const payloadHintBytes = 4096;

  if (dilithium?.reachable && falcon?.reachable) {
    log('Both sig services healthy — expect Dilithium by default on large payload', 'cyan');
    const r = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes });
    if (!r.ok) throw new Error(`/select/ake failed: ${r.json?.detail || r.status}`);
    if (r.json.schemeSelected !== 'dilithium') throw new Error(`expected dilithium, got ${r.json.schemeSelected}`);
    if (r.json.reason !== 'default_or_health') throw new Error(`expected reason default_or_health, got ${r.json.reason}`);
    if (!r.json.sharedSecretMatch) throw new Error('shared secrets mismatch');
    log('Defaulted to Dilithium OK', 'green');
    return true;
  }

  if (dilithium?.reachable && !falcon?.reachable) {
    log('Only Dilithium healthy — expect Dilithium by default', 'cyan');
    const r = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes });
    if (!r.ok) throw new Error(`/select/ake failed: ${r.json?.detail || r.status}`);
    if (r.json.schemeSelected !== 'dilithium') throw new Error(`expected dilithium, got ${r.json.schemeSelected}`);
    if (r.json.reason !== 'default_or_health') throw new Error(`expected reason default_or_health, got ${r.json.reason}`);
    if (!r.json.sharedSecretMatch) throw new Error('shared secrets mismatch');
    log('Defaulted to Dilithium (only healthy) OK', 'green');
    return true;
  }

  if (!dilithium?.reachable && falcon?.reachable) {
    log('Only Falcon healthy — expect Falcon by default', 'cyan');
    const r = await postJSON(`${ORCH}/select/ake`, { payloadHintBytes });
    if (!r.ok) throw new Error(`/select/ake failed: ${r.json?.detail || r.status}`);
    if (r.json.schemeSelected !== 'falcon') throw new Error(`expected falcon, got ${r.json.schemeSelected}`);
    if (r.json.reason !== 'default_or_health') throw new Error(`expected reason default_or_health, got ${r.json.reason}`);
    if (!r.json.sharedSecretMatch) throw new Error('shared secrets mismatch');
    log('Defaulted to Falcon (only healthy) OK', 'green');
    return true;
  }

  log('Neither signature service reachable — cannot run default selection', 'yellow');
  return { skipped: true, reason: 'no signature services reachable' };
}
