# Auto-Selector Orchestrator (PQC) — port 8090

A lightweight Fastify microservice that sits in front of your Kyber KEM and signature services (Dilithium, Falcon). It probes health, applies policy, and exposes a single "do the right thing" API for clients.

- Kyber KEM: expected at 8080 (separate service/repo)
- Dilithium: expected at 8081 (separate service/repo)
- Falcon: expected at 8083 (separate service/repo)
- Orchestrator/Auto-Selector (this repo): 8090

The orchestrator does NOT run PQC algorithms itself. It orchestrates the external PQC microservices.

## Features
- Health probing for Kyber, Dilithium, Falcon with latency/timeout tolerance
- Policy-based scheme selection:
  - Default preference: Dilithium + Kyber
  - Switch to Falcon + Kyber when payload is small (bandwidth constrained) or Dilithium is unhealthy
  - Honor explicit policy preference when healthy
- Single-call AKE flow: keypair → sign Kyber pub → encapsulate → decapsulate validation

## Quick start

### Local (Node 20+)
```bash
npm install
npm start
# Service listens on :8090
```

### Docker
Build and run only the orchestrator on 8090.
```bash
docker compose up --build
# or
docker build -t pqc-orchestrator .
docker run -p 8090:8090 pqc-orchestrator
```

Note: Kyber/Dilithium/Falcon live in other repos and must be reachable via network. By default the orchestrator will try `localhost` and `host.docker.internal` for each port. You can override with env vars.

## Configuration
Environment variables (optional overrides):
- `PORT` (default: 8090)
- `HOST` (default: 0.0.0.0)
- `KYBER_BASE` (e.g., `http://kyber.example:8080`)
- `DILITHIUM_BASE` (e.g., `http://dilithium.example:8081`)
- `FALCON_BASE` (e.g., `http://falcon.example:8083`)

The service also tries fallbacks: `http://localhost:<port>`, `http://127.0.0.1:<port>`, `http://host.docker.internal:<port>`.

## API

### GET /health
Returns health assessment and first reachable base for each backend.

Response example:
```json
{
  "status": "ok", // or "degraded"
  "kyber": { "reachable": true, "base": "http://localhost:8080" },
  "dilithium": { "reachable": true, "base": "http://localhost:8081" },
  "falcon": { "reachable": false, "base": null }
}
```

### POST /select/ake
Selects signature scheme based on policy and performs a one-shot AKE flow by orchestrating the PQC services.

Request body:
```json
{
  "payloadHintBytes": 800,            // optional: size hint; small payloads prefer Falcon
  "policyPreferredSig": "falcon",    // optional: "dilithium" | "falcon"
  "level": "aes256"                  // optional: security level hint; forwarded when available
}
```

Response example:
```json
{
  "status": "ok",
  "schemeSelected": "falcon",
  "reason": "payload_tight",
  "signerLevel": "aes256",
  "kyber": { "ciphertextLen": 1088 },
  "sharedSecretMatch": true
}
```

Errors:
```json
{ "error": "select_ake_failed", "detail": "Falcon unreachable" }
```

## Expected downstream endpoints
Your PQC services should expose the following endpoints (typical patterns):

Kyber service:
- `POST /kyber/generate-keypair` → `{ publicKey, secretKey }`
- `POST /kyber/decapsulate` → `{ sharedSecret }` (input: `{ secretKey, ciphertext }`)
- (If you provide verification, your signature service’s orchestrator endpoints will verify the signature on `kyberPublicKey` before encapsulation.)

Dilithium/Falcon service:
- `GET /orchestrator/signer` → `{ publicKey, level }`
- `POST /dilithium/sign` or `/falcon/sign` → `{ signature }` (if your service allows signing with an internal key)
- Or fallback: `POST /orchestrator/bootstrap` → `{ signature, isCompressed }`
- `POST /orchestrator/encapsulate-verified` → `{ ciphertext, sharedSecret }` (input includes `kyberPublicKey`, `signature`, `signerPublicKey`, `level`)

The orchestrator will try `/dilithium/sign` or `/falcon/sign` first; if the signature service requires hidden keys and doesn’t accept a missing `privateKey`, it will fall back to `/orchestrator/bootstrap`.

## Scheme selection policy
Order of decisions:
1. Health of Dilithium/Falcon services
2. Explicit `policyPreferredSig` if healthy
3. Payload size heuristic: if `payloadHintBytes <= 1024` and Falcon healthy → choose Falcon
4. Default: Dilithium if healthy; else Falcon if healthy; else error

Kyber availability is required for successful AKE.

## Development
- Codebase: `server.js` (Fastify, ESM)
- Dependencies: `fastify`
- Node 20+ recommended

### Run tests manually
- Ensure your PQC services are up and reachable.
- Try health:
```bash
curl -s localhost:8090/health | jq
```
- Try orchestration:
```bash
curl -s -X POST localhost:8090/select/ake \
  -H 'content-type: application/json' \
  -d '{"payloadHintBytes":512}' | jq
```

## Deployment tips
- Run orchestrator close to PQC services to minimize latency.
- Use env vars to point to production service URLs.
- Add container healthchecks for production.

## License
MIT
