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

export default async function testHealthSemantics() {
  const h = await getJSON(`${ORCH}/health`);
  if (!h.ok) throw new Error('orchestrator not reachable');
  const { status, kyber, dilithium, falcon } = h.json;

  if (!kyber) return { skipped: true, reason: 'health payload missing kyber' };

  const anySigReachable = !!(dilithium?.reachable || falcon?.reachable);
  const expectOk = kyber.reachable && anySigReachable;

  if (expectOk && status !== 'ok') throw new Error(`expected status ok, got ${status}`);
  if (!expectOk && status !== 'degraded') throw new Error(`expected status degraded, got ${status}`);

  // sanity: bases should be set only if reachable
  if (kyber.base && !kyber.reachable) throw new Error('kyber.base set while not reachable');
  if (dilithium?.base && !dilithium.reachable) throw new Error('dilithium.base set while not reachable');
  if (falcon?.base && !falcon.reachable) throw new Error('falcon.base set while not reachable');

  log(`Health semantics validated: ${status}`, 'green');
  return true;
}
