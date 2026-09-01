# Agent Trust Firewall

**A firewall for AI agents.** It sits between an agent and the API it is calling,
proves who is actually asking, scores how dangerous the request is, and blocks
the bad ones before they execute.

Live: <https://agent-trust-firewall.vercel.app>

## The problem

AI agents now book, pay and run code on their own. When one is compromised — a
leaked key, a poisoned prompt — its requests look exactly like a healthy
agent's: same credentials, same endpoints, no alarm. An API key proves someone
once had a secret; it does not prove that *this* request came from the agent you
think it did.

Everyone is building agents. Almost nobody is securing the handshake between
them.

## What it does

Every intercepted call must clear four checks before it runs:

1. **Sealed in transit** — the agent encrypts the call with a fresh key each time
   (X25519 + XChaCha20-Poly1305). Fields it marks sensitive are encrypted to the
   *destination*, and pass through the firewall unreadable.
2. **Identity, proved not claimed** — a Schnorr zero-knowledge proof of key
   possession. The key is never transmitted, and the proof is bound to one
   single-use challenge *and* one specific request.
3. **Authority, minimally disclosed** — a Merkle inclusion proof for the one
   capability this call needs. The firewall never learns the rest of the agent's
   grant set.
4. **Risk, scored and explained** — seven signals, including live lookups against
   public threat intelligence for the calling address, produce a 0–100 score in
   which every point traces back to a named reason in plain language.

Hard rules (revoked key, replayed proof, ungranted capability) block outright at
any configuration. They are not tunable.

## Try it

```bash
npm install
npm run dev        # http://localhost:3000
```

Runs with no configuration at all: with no `DATABASE_URL` it uses an in-process
store and seeds itself on boot. `/api/health` tells you which store is live.

### With durable storage

```bash
vercel integration add neon   # provisions Postgres, injects DATABASE_URL
vercel env pull .env.local
npm run seed                  # one time: ~500 statements, ~45s
```

Seeding is a deployment step rather than something the app does on demand.
Every seeded call is a real challenge, a real Schnorr proof and a real scoring
pass, which is genuinely expensive — running it inside a request would put tens
of seconds of database round-trips on a cold start.

Set `ATF_DEMO_SEED` to any high-entropy string when using a shared database, so
every instance derives the same demo-fleet keys as the ones enrolled in it. No
agent secret is ever stored.

Then open **/console/attack-range** and run an adversary. Each one is built for
real — a genuinely forged key, a genuinely replayed proof — and submitted through
the same decision path production traffic uses.

## Verify the claims

```bash
npm run test     # 163 tests, every attack scenario asserted
npm run verify   # 25 security invariants, printed one per line
npm run lint
npm run typecheck
npm audit        # 0 vulnerabilities
```

## The MCP server

```bash
npm run mcp
```

A real Model Context Protocol server over stdio. Every `tools/call` routes
through the firewall first; a blocked call returns a structured refusal and the
upstream tool is never invoked.

## External threat intelligence

The `intel` signal queries **GreyNoise Community** and **Shodan InternetDB** —
both keyless — for the address an agent calls from. **AbuseIPDB** and
**AlienVault OTX** activate when their keys are present (see `.env.example`);
without them the UI reports those providers as "not configured" rather than
failing.

All lookups are server-side, cached, rate-limit-safe, and degrade to
*synthetic only* on failure — which the UI states on the row, because presenting
an outage as a clean result would be worse than having no intel at all.

## Documentation

- `claude.md` — architecture and the security model
- `security.md` — posture, cryptography, known limitations
- `docs/security.md` — threat model and defence-by-attack
- `docs/decisions/` — why Schnorr rather than zkSNARKs, why hard rules sit
  outside the score

## Honest scope

The demo fleet is synthetic, but its keys, proofs, verdicts and origin addresses
are real — the addresses are live cloud hosts and the intelligence shown about
them is fetched at request time, so any of it can be checked. Risk tuning is
sandboxed per visitor, so nothing you change affects anyone else. And a firewall
must read a request to score it, so ATF is a trusted endpoint for the outer
envelope; only destination-sealed fields are opaque to it.
