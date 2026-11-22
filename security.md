# Security Policy

## Reporting a vulnerability

Please report security issues **privately** to the maintainer via
GitHub (<https://github.com/krishnashahane>) rather than opening a public issue.
Include steps to reproduce and impact. You'll get an acknowledgement as soon as
possible.

This project is security infrastructure, so a report about ATF's own posture —
not just its firewall logic — is in scope and welcome.

## Posture

- **No secrets are required to run it.** ATF needs no database credentials and no
  auth provider, and the two threat-intelligence providers it relies on are
  keyless. Everything in `.env.example` is optional: two provider keys that
  activate extra sources, and `ATF_GATEWAY_SECRET_KEY`, which pins the gateway
  keypair across restarts. All are server-side only.
- **No secret is ever returned to a client.** The gateway's X25519 secret lives
  only in `src/lib/atf/gateway.ts` and no route serialises it. Agent secret keys
  never enter the system at all — an agent proves possession with a
  proof of key possession, and the protocol has no field that could carry a key.
- **No unauthenticated write touches shared state.** Risk configuration is
  sandboxed per visitor behind an opaque HttpOnly cookie; the shared config is
  read-only. Hard rules stay in force in every sandbox.
- **Every route validates and rate-limits.** All API routes compose
  `originGuard` → `limit` → `readJson(schema)` (`src/lib/guard.ts`). Cross-site
  browser requests to state-changing endpoints are rejected; bodies are capped at
  512 KB and validated with Zod before a handler sees them.
- **Errors are opaque.** `fail()` logs the real error server-side and returns a
  reference id. Every envelope-decryption failure returns one identical message,
  so a prober cannot use error text as a decryption oracle.
- **The audit log stores digests, never payloads.** `npm run verify` asserts this
  with a canary value that must not appear in the log or the traffic feed.
- **Headers.** `src/proxy.ts` sets a nonce-based CSP with no `unsafe-inline` for
  scripts and no external origin allowlisted, plus HSTS, `frame-ancestors 'none'`,
  `nosniff`, `Referrer-Policy: no-referrer`, a restrictive Permissions-Policy and
  COOP/CORP.
- **Attacker-controlled input never drives unbounded work.** Argument traversal
  is depth- and size-capped, Merkle path length is capped, the in-memory store
  evicts, and rate-limit buckets are pruned.

## External lookups

`/api/osint` accepts an address and fetches it from third parties, which is an
SSRF primitive unless constrained. `isPublicIpv4` refuses private, loopback,
link-local (including `169.254.169.254`), CGNAT, benchmark, multicast and
reserved ranges, and rejects octal-looking octets rather than coercing them.
`npm run verify` asserts this.

Provider API keys are read server-side only and are never prefixed
`NEXT_PUBLIC_`. Responses are cached (30 min success, 2 min failure) and
in-flight requests de-duplicated, so a refresh storm cannot exhaust a free tier.
Every provider call has a 4s timeout and fails closed to "no intel" rather than
to "clean".

## Cryptography

Audited primitives only — `@noble/curves`, `@noble/hashes`, `@noble/ciphers`.
Nothing here is hand-rolled maths.

| Purpose | Construction |
|---|---|
| Identity | Schnorr proof of possession (Fiat–Shamir; equivalently a Schnorr signature) over ed25519's prime-order group |
| Selective disclosure | Merkle tree, domain-separated leaf and node hashes |
| Transport | X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305 AEAD |
| Integrity | SHA-256 hash chain |

All hashing is domain-tagged and length-prefixed, so a digest from one protocol
step can never be replayed as a digest for another. Verification paths use
constant-time comparison and return `false` rather than throwing on malformed
input, so a hostile caller cannot turn a parse error into a different code path.

## Known limitations

Stated here and on the landing page rather than glossed over.

1. **Storage is durable when configured.** With `DATABASE_URL` set the audit log
   and traffic history live in Postgres and survive restarts; without it the same
   code uses an in-process store that does not. `/api/health` reports which.
2. **Rate limits are shared only with a database.** With `DATABASE_URL` set, every
   instance counts against one Postgres-backed window per client and route.
   Without it, or if the database is unreachable, each instance enforces the
   limit on its own.
3. **ATF reads the outer envelope.** A firewall that scores a request must be
   able to read it, so ATF is by design a trusted endpoint for that layer. Only
   fields an agent seals to the destination stay opaque to it.
4. **Payload inspection is heuristic.** Injection and credential patterns will
   have false positives and false negatives. That is why they *escalate to FLAG*
   rather than block outright — a human should see them.
5. **Scope is the MCP ecosystem.** ATF secures calls that pass through the
   interceptor. It is not an internet-scale agent mesh.

## Verifying the claims yourself

```bash
npm run test     # 224 tests, including every attack scenario as an assertion
npm run verify   # 30 security invariants, printed one per line
npm audit --omit=dev   # 0 vulnerabilities in shipped dependencies
```

`npm run verify` checks the load-bearing properties directly: an unenrolled agent
is blocked, a replayed proof is blocked, a proof cannot be moved onto a different
request, a hard rule cannot be tuned away at any configuration, the firewall
cannot open a destination-sealed field, an altered or deleted audit record is
detected, and no argument value or secret key is ever retained.
