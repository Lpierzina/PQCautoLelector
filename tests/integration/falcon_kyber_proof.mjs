#!/usr/bin/env node

const FALCON_BASE = process.env.FALCON_BASE || 'http://localhost:8083';
const KYBER_BASE = process.env.KYBER_BASE || 'http://localhost:8080';

function log(message, color = '') {
  const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    bright: '\x1b[1m',
    reset: '\x1b[0m'
  };
  console.log(`${colors[color] || ''}${message}${colors.reset}`);
}

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.json();
}

async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const t = await r.text();
  if (!r.ok) throw new Error(t || `${r.status}`);
  return t ? JSON.parse(t) : {};
}

export default async function proveFalconUsesKyber() {
  log('Checking service health...', 'blue');
  const falconHealth = await get(`${FALCON_BASE}/health`);
  const kyberHealth = await get(`${KYBER_BASE}/health`);

  if (!falconHealth) return { skipped: true, reason: 'falcon unreachable' };
  if (!kyberHealth) return { skipped: true, reason: 'kyber unreachable' };

  log('Getting Falcon signer from orchestrator...', 'blue');
  const { level: falconLevel, publicKey: falconPublicKey } = await get(`${FALCON_BASE}/orchestrator/signer`);

  log('Bootstrapping: Generate Kyber keys + Falcon signature...', 'blue');
  const bootstrap = await post(`${FALCON_BASE}/orchestrator/bootstrap`, {});

  const { kyberPublicKey, kyberSecretKey, falconSignerPublicKey, signature, isCompressed } = bootstrap;

  if (!kyberPublicKey || !signature || !falconSignerPublicKey) {
    throw new Error('bootstrap did not return expected fields');
  }

  log('Verifying Falcon signature over Kyber public key...', 'blue');
  const verify = await post(`${FALCON_BASE}/falcon/verify`, {
    messageBase64: kyberPublicKey,
    signature,
    publicKey: falconSignerPublicKey,
    level: falconLevel
  });

  if (!verify.valid) throw new Error('signature invalid over kyber public key');

  log('Using orchestrator to encapsulate with verified Kyber key...', 'blue');
  const encap = await post(`${FALCON_BASE}/orchestrator/encapsulate-verified`, {
    kyberPublicKey,
    signature,
    signerPublicKey: falconSignerPublicKey,
    level: falconLevel
  });

  log('Decapsulating to complete the key exchange...', 'blue');
  const decap = await post(`${KYBER_BASE}/kyber/decapsulate`, {
    secretKey: kyberSecretKey,
    ciphertext: encap.ciphertext
  });

  if (encap.sharedSecret !== decap.sharedSecret) {
    throw new Error('shared secrets mismatch');
  }

  log('Falcon successfully used Kyber with authenticated key exchange', 'green');
  return true;
}
