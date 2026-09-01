# Agent Trust Firewall (ATF)

A **firewall for AI agents**. It sits between an agent and the API (or other
agent) it is calling, proves who is actually asking, scores how dangerous the
request is, and blocks the bad ones *before* they execute.

The problem it exists for: agents now book, pay and run code autonomously, and a
compromised agent's requests look identical to a healthy one's — same
credentials, same endpoints, no alarm. Nothing today checks the handshake.

## The decision path

Every intercepted call goes through exactly this, in `src/lib/atf/interceptor/decide.ts`:

```
open envelope → verify identity → spend nonce → prove capability
              → build context → score → apply policy → write audit record
```

Every step is **fail-closed**. An error anywhere produces a BLOCK with a stated
reason, never a silent pass.

## Architecture

Three separable pieces, by design — the risk engine knows nothing about HTTP, and
nothing in `src/lib/atf/` imports Next.js.

| Path | Role |
|---|---|
| `src/lib/atf/identity/schnorr.ts` | Fiat–Shamir Schnorr NIZK over ed25519. Proves key possession; the challenge binds the nonce **and** the request digest, so a proof works for exactly one call. |
| `src/lib/atf/identity/merkle.ts` | Capability grants as a Merkle tree. An agent discloses one capability plus an inclusion proof, never its whole grant set. Leaf and node hashes are domain-separated. |
| `src/lib/atf/identity/nonce.ts` | Single-use, agent-bound, TTL'd challenges. The replay defence. |
| `src/lib/atf/identity/registry.ts` | Enrolment, rotation, revocation. Public keys only. |
| `src/lib/atf/crypto/e2ee.ts` | X25519 → HKDF-SHA256 → XChaCha20-Poly1305 sealed envelopes. Ephemeral sender key per envelope (forward secrecy); agent id + request digest bound as AEAD associated data. |
| `src/lib/atf/crypto/sealed.ts` | Two-layer sealing. Fields marked sensitive are sealed to the **destination**, so ATF scores them by verified descriptor (size, entropy, shape) without reading them. |
| `src/lib/atf/risk/signals/*.ts` | One file per signal: identity, context, behavior, rate, payload, reputation, intel. Each returns `{score, evidence}` — the evidence is a sentence, not a code. |
| `src/lib/atf/osint/*.ts` | Live third-party threat intelligence. `providers.ts` holds one function per source (GreyNoise + Shodan keyless; AbuseIPDB + OTX key-gated), `index.ts` fans out, merges worst-case, and caches hard. `net.ts` restricts lookups to public IPv4 — the SSRF control. |
| `src/lib/atf/risk/engine.ts` | Pure weighted composition → `{score 0-100, band, contributions[]}`. Deterministic, and every point is attributable. |
| `src/lib/atf/interceptor/policy.ts` | Hard rules (unconditional BLOCK) and escalations (unconditional minimum FLAG). |
| `src/lib/atf/audit/chain.ts` | SHA-256 hash-chained log. `verifyChain()` names the exact record that broke. |
| `src/lib/atf/session.ts` | Per-visitor config sandboxes. Bounded, TTL'd, cookie-keyed; keeps one visitor's tuning off another's screen. |
| `src/lib/atf/store/port.ts` | The storage interface. `memory.ts` is the only implementation; a Postgres one drops in without touching the engine. |
| `src/lib/atf/mcp/server.ts` | A real MCP stdio server. Every `tools/call` routes through `decide()`; blocked calls never reach the tool. |
| `src/lib/atf/client.ts` | Agent-side SDK. Holds the secret key, builds the proofs, seals the envelope. There is no field in the protocol that could carry a secret key. |

## Security model

Read `src/lib/guard.ts` before touching any API route. Every route composes, in
this order: `originGuard` → `limit` → `readJson(schema)`.

- **Hard rules are not tunable.** Unknown agent, revoked key, unverified proof,
  replayed challenge, ungranted capability ⇒ BLOCK at *every* configuration.
  `/api/config` can move weights and thresholds; it cannot disable these.
- **Configuration is per-visitor, never global.** Applying a config writes to a
  sandbox keyed by an opaque HttpOnly cookie (`src/lib/atf/session.ts`), bounded
  and TTL'd; the shared gateway config is read-only from every request path. The
  original design mutated the single shared config, which let any anonymous
  visitor change scoring for everyone else — an unauthenticated global state
  mutation, in a firewall. `tests/session.test.ts` asserts the isolation and
  that a sandbox still cannot disable a hard rule.
- **Escalations.** A confident payload detection (prompt injection, credential
  shape) forces at least a FLAG regardless of the weighted score — heuristics
  should reach a human, not be averaged away.
- **No secret ever leaves the server.** The gateway's X25519 secret lives only in
  `gateway.ts`; no route serialises it. Agent secret keys never enter the system
  at all.
- **The audit log stores digests, not payloads.** An audit log that leaks what it
  audits is a liability. `npm run verify` asserts this with a canary value.
- **Opaque errors.** `fail()` logs the real error server-side and returns a
  reference id. Envelope failures all return one identical message, so a prober
  gets no decryption oracle.
- **CSP.** `src/proxy.ts` sets a per-request nonce and `script-src 'self'
  'nonce-…' 'strict-dynamic'` — no `unsafe-inline` for scripts. The one inline
  script (the no-flash theme initialiser) carries the nonce. No external origin
  is allowlisted anywhere, because the app loads nothing external.
- **Bounded everything.** Argument traversal is depth- and size-capped, Merkle
  path length is capped, the memory store evicts, rate limits are per route and
  per client. Attacker-controlled input never drives unbounded work.

## External intelligence

The `intel` signal is the only one fed by data ATF did not generate, so it obeys
two extra rules:

- **Absent intel scores zero, never "clean."** A provider outage must not read as
  a good reputation. The UI labels every row *live intel* or *synthetic only*.
- **It cannot block alone.** Addresses are shared, recycled and mislabelled, so
  external reputation raises the score and names its provider; it is never a hard
  rule.

Lookups are server-side only (`/api/osint`), cached 30 minutes on success and 2
minutes on failure, de-duplicated in flight, and capped at a 4s timeout per
provider. Request paths read the cache (`peekIp`) and warm it in the background
(`warmIp`) rather than awaiting providers — blocking `/api/agents` on a dozen
third-party round-trips put their latency into our own cold start. `isPublicIpv4` refuses private, loopback, link-local and CGNAT ranges —
without it, an endpoint that fetches a user-supplied address is an SSRF
primitive.

The demo fleet's addresses are real public addresses; the *agents* are synthetic
and the UI says so. Nothing about their reputation is hardcoded.

## Design system

`globals.css` is the single source for colour, type, the 8px spacing scale, and
motion tokens (`--d-*`, `--e-*`). **Light is the default**, defined on bare
`:root`; dark exists only under `[data-theme="dark"]`, and `prefers-color-scheme`
is deliberately not consulted — a console that changes appearance from an OS
setting the operator did not apply here is a surprise, not a feature.

Motion lives in `src/components/motion/` — `Reveal`, `Counter`, `useSequence`,
`useDebounced`, all built on CSS transitions plus one IntersectionObserver, with
no animation dependency. Every primitive *derives* from `useReducedMotion()`
rather than writing state when it changes, so content is never left invisible
waiting for an animation that will not run.

**Never hardcode a colour in a component** — add a token instead. Verdict colour
is always paired with the verdict word, because colour alone is not an accessible
signal.

## Honest scope

- Storage is in-process; history resets on cold start. The port exists so this is
  a swap, not a rewrite.
- The demo fleet is synthetic. Its keys, proofs, scores and verdicts are not —
  seeding runs real proofs through the real engine at backdated timestamps.
- A firewall must read a request to score it, so ATF is a trusted endpoint for
  the outer envelope. Only destination-sealed fields are opaque to it. This is
  stated on the landing page rather than glossed over.

## Commands

```bash
npm run dev        # local dev
npm run build      # production build
npm run lint       # eslint
npm run typecheck  # tsc --noEmit
npm run test       # 163 tests: crypto, signals, engine, interceptor, audit, MCP, guards, scenarios, OSINT
npm run verify     # 25 security invariants, asserted outside the test runner
npm run mcp        # the MCP stdio server
```

## Deployed

<https://agentwall-pbl.vercel.app> — the single canonical domain.

`agentwall.vercel.app` and `agent-wall.vercel.app` are claimed by other accounts.
A `.vercel.app` name returning 404 does **not** mean it is free — a
claimed-but-empty project answers the same way, so the only reliable test is
attempting the alias.
