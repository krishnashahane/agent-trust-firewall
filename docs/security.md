# Security posture, in detail

This document is the long form of `security.md`. It explains what each defence
is for, what it does not cover, and how to check it.

## Threat model

ATF assumes an attacker who has one or more of:

- **network position** — can observe and replay traffic between an agent and an API
- **a compromised agent** — holds a real, enrolled agent's credentials
- **influence over agent inputs** — can get text of their choosing into an
  agent's tool arguments (poisoned documents, hostile user input)
- **an invented identity** — can generate keys and call endpoints directly

It does **not** assume an attacker with code execution inside the firewall
process. Nothing defends against that, here or anywhere; if the firewall is
compromised, the firewall is compromised.

## Defence by attack

| Attack | Defence | Where |
|---|---|---|
| Calling as an agent you are not | Schnorr NIZK against the enrolled public key | `identity/schnorr.ts` |
| Replaying a captured proof | Single-use, agent-bound, TTL'd challenge, spent on *attempt* | `identity/nonce.ts`, `store/memory.ts` |
| Moving a proof onto a richer request | Challenge commits to the request digest | `schnorr.ts`, `interceptor/decide.ts` |
| Using authority you were not granted | Merkle inclusion proof + namespace/action matching | `identity/merkle.ts`, `risk/signals/context.ts` |
| Continuing to call after revocation | Revocation checked as a hard rule, before scoring | `interceptor/policy.ts` |
| Reading traffic off the wire | X25519 + XChaCha20-Poly1305 sealed envelopes | `crypto/e2ee.ts` |
| Re-attributing an envelope to another agent | Agent id and request digest bound as AEAD associated data | `crypto/e2ee.ts` |
| Decrypting yesterday's traffic with today's stolen key | Fresh ephemeral sender key per envelope | `crypto/e2ee.ts` |
| Hijacking a downstream model | Prompt-injection pattern scan, escalating to FLAG | `risk/signals/payload.ts` |
| Smuggling secrets out in arguments | Credential-shape and entropy/size analysis | `risk/signals/payload.ts` |
| Draining an API in a burst | Sliding window + burst ratio against the agent's own pace | `risk/signals/rate.ts` |
| Acting normal-looking but out of character | Per-agent baseline of tool, destination and hour | `risk/signals/behavior.ts` |
| Covering tracks afterwards | SHA-256 hash chain; any edit or deletion breaks verification | `audit/chain.ts` |
| Lying about an encrypted field's contents | Descriptor re-derived from ciphertext length | `crypto/sealed.ts` |
| Exhausting the firewall | Depth/size caps, path caps, eviction, rate limits | throughout |

## Why hard rules exist separately from the score

A weighted score is a judgement, and judgements can be tuned. If "this key was
revoked" were merely a heavy signal, a permissive threshold would let it
through — and someone would eventually set one. So the failures that mean the
security model itself has been violated bypass scoring entirely:

`unknown-agent`, `revoked-key`, `identity-unproven`, `replayed-challenge`,
`capability-unproven`, `capability-escalation`.

`npm run verify` asserts that these still BLOCK with every weight at zero and
both thresholds at 100 — the most permissive configuration the schema allows.

## Why escalations exist

The mirror problem: payload detection carries a modest weight, so a textbook
prompt injection from an otherwise well-behaved agent could score below the flag
threshold and be silently allowed. This was a real gap found by the test suite,
not a hypothetical.

The fix is an escalation floor: a payload signal at or above 0.75 forces at least
a FLAG, whatever the weighted total. It escalates rather than blocks because
these are heuristics with false positives — the right outcome is that a human
sees it, not that a legitimate call dies.

## What the audit log deliberately does not contain

Argument values. Tool names, destinations, agent ids, verdicts, scores and a
digest of the request — enough to reconstruct what was decided and prove it was
not altered, and not enough to leak what was in the call. `npm run verify` sends
a canary value through and asserts it appears in neither the audit log nor the
traffic feed.

## The CSP decision

`src/proxy.ts` issues a per-request nonce and sets
`script-src 'self' 'nonce-…' 'strict-dynamic'`. No `unsafe-inline` for scripts.

This is possible because every page here renders dynamically (`export const
dynamic = "force-dynamic"`), so there is a request to attach a nonce to. A
statically prerendered page has no per-request nonce to stamp into build-time
HTML, which is the usual reason projects fall back to `unsafe-inline`. The cost
is that pages are not statically cached; for a live security console that was
never going to be useful anyway.

`style-src` does keep `'unsafe-inline'`, which Next's inlined critical CSS
requires. Styles are a materially smaller injection surface than scripts, and the
alternative is shipping no critical CSS.

## Residual risk

- In-process storage: history is lost on cold start (see `store/port.ts`).
- Per-instance rate limiting: a multi-instance deployment multiplies the limit.
- Heuristic payload analysis: pattern lists will always lag novel phrasings.
- The gateway is a trusted endpoint for the outer envelope, by necessity.
