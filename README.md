# Agent Trust Firewall

**A firewall for AI agents.** It sits between an agent and the API (or other
agent) it is calling, proves who is actually asking, scores how dangerous the
request is, and blocks the bad ones before they execute.

Live: <https://agentwall-pbl.vercel.app>

## The problem

AI agents now book, pay and run code on their own. When one is compromised — a
leaked key, a poisoned prompt — its requests look exactly like a healthy
agent's: same credentials, same endpoints, no alarm. An API key proves someone
once had a secret; it does not prove that *this* request came from the agent you
think it did, that the agent is allowed to do *this*, or that the request is
not a replay of yesterday's.

## What it does

Every intercepted call must clear four checks before it runs:

1. **Sealed in transit** — the agent encrypts the call with a fresh key each time
   (X25519 → HKDF-SHA256 → XChaCha20-Poly1305). Fields it marks sensitive are
   encrypted to the *destination* and pass through the firewall unreadable.
2. **Identity, proved not claimed** — a Schnorr zero-knowledge proof of key
   possession. The key is never transmitted, and the proof is bound to one
   single-use challenge *and* one specific request, so it cannot be replayed or
   moved onto a different call.
3. **Authority, minimally disclosed** — a Merkle inclusion proof for the one
   capability this call needs. The firewall never learns the rest of the agent's
   grant set.
4. **Risk, scored and explained** — seven signals (identity, context, behaviour,
   rate, payload, reputation, live threat intel) produce a 0–100 score in which
   every point traces back to a named reason in plain language.

The outcome is **ALLOW**, **FLAG** (hold for a human) or **BLOCK**, and every
decision is written to a SHA-256 hash-chained audit log.

**Hard rules are not tunable.** Unknown agent, revoked key, unverified proof,
replayed challenge and ungranted capability block at *every* configuration. A
confident prompt-injection or credential-leak detection forces at least a FLAG
whatever the weighted score says.

## Quick start

Requires **Node.js 22.6 or newer** (the `verify`, `mcp` and `seed` scripts run
TypeScript directly with `--experimental-strip-types`). Production runs on
Node 24.

```bash
npm install
npm run dev        # http://localhost:3000
```

It runs with no configuration at all: without `DATABASE_URL` it uses an
in-process store and seeds a demo fleet of six agents with half an hour of real
traffic on boot. `/api/health` tells you which store is live.

## Using it

### The console

| Page | What it is for |
|---|---|
| `/` | What ATF is, with a live decision running in the hero |
| `/console` | Live traffic: every decision, its score, and why |
| `/console/attack-range` | Run an adversary (forged identity, replay, revoked key, capability escalation, rate flood, off-baseline behaviour, prompt injection, credential exfiltration) through the real decision path and watch the verdict |
| `/console/agents` | The enrolled fleet, with live external threat intel per origin address |
| `/console/tuning` | Move signal weights and thresholds and preview what that would have done to recent traffic. Sandboxed to your browser — it never changes anyone else's scoring, and cannot disable a hard rule |
| `/console/audit` | The hash-chained audit log and a live tamper check |
| `/glossary` | Every term in plain language |

### Calling it as an agent

An agent integrates with the SDK in `src/lib/atf/client.ts`. The flow, all
over plain HTTP:

```ts
import { generateKeyPair } from "./src/lib/atf/identity/schnorr.ts";
import { generateEncryptionKeyPair, open } from "./src/lib/atf/crypto/e2ee.ts";
import { signCall, sealCall } from "./src/lib/atf/client.ts";

const BASE = "http://localhost:3000";
const post = (path: string, body: unknown) =>
  fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());

// 1. Enrol once. Only public keys are sent.
const signing = generateKeyPair();
const encryption = generateEncryptionKeyPair();
const capabilities = ["calendar:createEvent", "search:query"];
await post("/api/agents/register", {
  agentId: "my-agent",
  displayName: "My agent",
  signingPublicKey: signing.publicKey,
  encryptionPublicKey: encryption.publicKey,
  capabilities,
});

// 2. Per call: get a single-use challenge, prove, seal, submit.
const { publicKey: gatewayKey } = await fetch(BASE + "/api/gateway/pubkey").then((r) => r.json());
const { nonce } = await post("/api/agents/challenge", { agentId: "my-agent" });
const call = signCall(
  { agentId: "my-agent", signingSecretKey: signing.secretKey, capabilities },
  {
    tool: "calendar.createEvent",
    destination: "calendar.example.com",
    capability: "calendar:createEvent",
    args: { title: "Design review" },
    nonce,
  },
);
const { sealed } = await post("/api/gateway/intercept", {
  envelope: sealCall(gatewayKey, call),
  replyTo: encryption.publicKey, // the verdict comes back sealed to you
});
const verdict = open(encryption.secretKey, sealed); // { verdict: "ALLOW", score, explanation, ... }
```

Capabilities are `namespace:action` and must match the tool exactly
(`calendar:createEvent` authorises `calendar.createEvent`) or by wildcard
(`calendar:*`). Holding `calendar:write` does **not** authorise
`calendar.createEvent`; that is a `capability-escalation` and is blocked.

Submitting `{ "call": … }` instead of `{ "envelope": … }` is accepted for
integrators who terminate encryption elsewhere; the response reports
`transport: "plaintext"` rather than implying protection that was not applied.
A BLOCK on the plaintext path returns HTTP 403.

### API

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Liveness, storage backend, audit chain validity |
| `/api/agents` | GET | Enrolled fleet with intel |
| `/api/agents/register` | POST | Enrol an agent (public keys + capabilities) |
| `/api/agents/challenge` | POST | Issue a single-use, agent-bound challenge |
| `/api/gateway/pubkey` | GET | The gateway's X25519 public key |
| `/api/gateway/intercept` | POST | Submit a call for a decision |
| `/api/traffic` | GET | Recent decisions and a summary |
| `/api/audit`, `/api/audit/verify` | GET | Audit log; chain verification |
| `/api/config` | GET / PUT / DELETE | Read, set or clear *your* risk-config sandbox |
| `/api/config/preview` | POST | Re-score recent traffic against a proposed config |
| `/api/simulate` | GET / POST | List or run attack-range scenarios |
| `/api/sealed-demo` | POST | Show a destination-sealed field passing through unread |
| `/api/osint` | POST | Threat intel for a public IPv4 address |

Every route applies, in order, an origin check (cross-site browser requests are
refused), a per-client rate limit, and Zod schema validation of the body.

### The MCP server

```bash
npm run mcp
```

A real Model Context Protocol server over stdio (JSON-RPC 2.0, one message per
line). Every `tools/call` is routed through the same `decide()` path as the HTTP
gateway; a blocked call returns a structured refusal with `isError: true` and
the upstream tool is never invoked. To use it from an MCP client, point the
client at:

```json
{
  "command": "node",
  "args": ["--experimental-strip-types", "src/lib/atf/mcp/server.ts"],
  "cwd": "/path/to/agent-trust-firewall"
}
```

The server fronts three demo tools (`search.query`, `payments.charge`,
`storage.read`) and runs as a demo agent holding a subset of capabilities, so
you can see one call allowed and another blocked. It keeps its own in-process
store.

## Architecture

Three separable layers. The risk engine knows nothing about HTTP, and nothing
in `src/lib/atf/` imports Next.js.

```
agent ──sealed envelope──▶ /api/gateway/intercept  (or MCP tools/call)
                                   │
                                   ▼
              src/lib/atf/interceptor/decide.ts
   open envelope → verify identity → spend nonce → prove capability
               → build context → score → apply policy → audit
                                   │
                                   ▼
                ALLOW / FLAG / BLOCK  + hash-chained audit record
```

Every step is fail-closed: an error anywhere produces a BLOCK with a stated
reason, never a silent pass.

| Path | Role |
|---|---|
| `src/lib/atf/identity/` | Schnorr NIZK, Merkle capability proofs, single-use nonces, agent registry |
| `src/lib/atf/crypto/` | Sealed envelopes and destination-sealed fields |
| `src/lib/atf/risk/` | One file per signal, plus a pure weighted engine |
| `src/lib/atf/interceptor/` | The decision path, hard rules and escalations |
| `src/lib/atf/osint/` | GreyNoise, Shodan InternetDB, AbuseIPDB, OTX — cached, SSRF-guarded |
| `src/lib/atf/audit/chain.ts` | SHA-256 hash chain; `verifyChain()` names the record that broke |
| `src/lib/atf/store/` | Storage port with in-memory and Postgres implementations |
| `src/lib/atf/mcp/server.ts` | The MCP stdio server |
| `src/lib/atf/client.ts` | Agent-side SDK |
| `src/lib/guard.ts` | Origin check, rate limit, body validation, opaque errors |
| `src/proxy.ts` | Security headers and a per-request CSP nonce |
| `src/app/` | Next.js App Router pages and API routes |

`claude.md` has the long-form architecture and security model.

## Configuration

Nothing is required. Every variable is optional and server-side only — never
prefix any of them with `NEXT_PUBLIC_`. See `.env.example`.

| Variable | Effect when set |
|---|---|
| `DATABASE_URL` | Durable Postgres (Neon) storage instead of the in-process store |
| `ATF_DEMO_SEED` | Derives the demo fleet's keys deterministically. **Required with a shared database**, so every instance signs with the keys that are enrolled |
| `ATF_GATEWAY_SECRET_KEY` | Pins the gateway's X25519 keypair (64 hex chars). **Set it on any multi-instance deployment** — otherwise each instance has its own key and an envelope sealed to one cannot be opened by another |
| `ABUSEIPDB_API_KEY` | Adds AbuseIPDB to threat intel |
| `OTX_API_KEY` | Adds AlienVault OTX to threat intel |

Generate the two secrets with `openssl rand -hex 32`.

## Deployment (Vercel)

```bash
vercel link                      # once
vercel integration add neon      # provisions Postgres, injects DATABASE_URL
vercel env add ATF_DEMO_SEED production
vercel env add ATF_GATEWAY_SECRET_KEY production
vercel env pull .env.local
npm run seed                     # once per fresh database: ~500 statements, ~45s
vercel --prod
```

Seeding is a deployment step rather than something the app does on demand.
Every seeded call is a real challenge, a real Schnorr proof and a real scoring
pass; running that inside a request would put tens of seconds of database
round-trips on a cold start. `npm run seed` is safe to re-run — it does nothing
if the store already holds traffic. With Postgres configured, the app registers
the demo fleet on boot but never seeds traffic itself.

`vercel.json` pins the region to `bom1`. Every page renders dynamically so the
CSP can carry a per-request nonce.

## Verifying the claims

```bash
npm run lint
npm run typecheck
npm run test           # 172 tests: crypto, signals, engine, interceptor, audit, MCP, guards, scenarios, OSINT
npm run verify         # 25 security invariants, printed one per line
npm run build
npm audit              # 0 vulnerabilities, including dev tooling
```

`npm run verify` checks the load-bearing properties directly, outside the test
runner: an unenrolled agent is blocked, a replayed proof is blocked, a proof
cannot be moved onto a different request, a hard rule cannot be tuned away at
any configuration, the firewall cannot open a destination-sealed field, an
altered or deleted audit record is detected, and no argument value or secret key
is ever retained.

## Security

- **No secret leaves the server.** The gateway's X25519 secret lives only in
  `gateway.ts`; agent secret keys never enter the system, and the protocol has
  no field that could carry one.
- **The audit log stores digests, not payloads.** `npm run verify` asserts this
  with a canary value.
- **Opaque errors.** Unexpected failures return a reference id, and every
  envelope failure returns one identical message, so a prober gets no
  decryption oracle.
- **Strict CSP.** Nonce-based `script-src` with no `unsafe-inline` and no
  external origins, plus HSTS, `frame-ancestors 'none'`, `nosniff`,
  `no-referrer`, COOP/CORP.
- **SSRF-guarded intel.** Lookups accept public IPv4 only — private, loopback,
  link-local (including cloud metadata), CGNAT and reserved ranges are refused.
- **Bounded work.** Argument traversal, Merkle path length, request bodies
  (512 KB), the in-memory store and rate-limit buckets are all capped.

See `security.md` for the posture and how to report a vulnerability,
`docs/security.md` for the threat model, and `docs/decisions/` for why Schnorr
rather than zkSNARKs, and why hard rules sit outside the score.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `/api/health` says `in-process (resets on cold start)` | `DATABASE_URL` is not set. Expected locally; set it for durable history |
| Console is empty on a Postgres deployment | The database has not been seeded. Run `npm run seed` with `DATABASE_URL` set |
| Attack-range calls intermittently fail with `identity-unproven` | `ATF_DEMO_SEED` is unset with a shared database, so instances fight over the fleet's keys. Set it and redeploy |
| An agent gets `Envelope could not be opened.` intermittently | `ATF_GATEWAY_SECRET_KEY` is unset on a multi-instance deployment. Pin it and redeploy. `/api/health` reports `gatewayKeyPinned` |
| A legitimate call is blocked with `capability-escalation` | The proved capability does not match the tool. Grant `namespace:action` matching the tool name, or `namespace:*` |
| `replayed-challenge` | Each challenge is single-use and expires. Request a fresh one per call |
| `403 Cross-site requests are not accepted here.` | A browser on another origin called a state-changing route. Call from the same origin or from a server (no `Origin` header) |
| `429 Too many requests` | Per-client, per-route rate limit. Wait a minute |
| Intel rows say *synthetic only* | Providers were unreachable or timed out (4s). That is reported, never shown as a clean result |
| `npm run verify` / `mcp` fails with an unknown flag | Node is older than 22.6. Upgrade Node |

## Honest scope

The demo fleet is synthetic, but its keys, proofs, verdicts and origin
addresses are real — the addresses are live cloud hosts and the intelligence
shown about them is fetched at request time. Rate limiting is per instance.
Payload inspection is heuristic, which is why it escalates to FLAG rather than
blocking. And a firewall must read a request to score it, so ATF is a trusted
endpoint for the outer envelope; only destination-sealed fields are opaque to
it.

## License

MIT — see `LICENSE`.
