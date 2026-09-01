# ADR 0001 — Schnorr NIZK rather than a zkSNARK circuit

**Status:** accepted
**Date:** 2026-09-01

## Context

The product claims "zero-knowledge identity verification". That phrase points at
a wide range of constructions, from a Groth16 circuit proving set membership down
to a signature scheme that is not zero-knowledge at all. We had to pick one and
be able to defend the wording.

## Options

1. **Groth16 zkSNARK** — prove "this agent is in the allowlist" without revealing
   which agent. The most impressive claim available.
2. **Schnorr NIZK (Fiat–Shamir)** — prove possession of the secret key behind an
   enrolled public key, without transmitting the key.
3. **Ed25519 signed attestations** — a plain challenge-response signature.

## Decision

Option 2, plus Merkle-proof selective disclosure of capabilities.

## Rationale

Option 3 would have meant dropping "zero-knowledge" from the copy, because a
signature over a challenge is not a zero-knowledge proof. We were not willing to
either overstate it or lose the property.

Option 1 is genuinely stronger for *anonymity* — but anonymity is not the
property this firewall needs. ATF must know which agent is calling in order to
score it against its own baseline and reputation; an anonymous agent cannot have
a behavioural baseline. A circuit hiding the agent's identity would have made the
risk engine strictly worse while adding proving keys, trusted setup artifacts,
multi-second proving times and a large dependency surface to a security product
whose main virtue is that it is small and auditable.

Option 2 delivers the property that actually matters: the secret key is never
transmitted, not even encrypted, and never stored by the firewall. Combined with
Merkle disclosure, the firewall learns *one* capability rather than the agent's
whole grant set — genuine minimum disclosure at the layer where it helps.

## Consequences

- The claim we make is exactly what the code does: possession is proved in zero
  knowledge, and the capability set is selectively disclosed.
- Proof and verification are sub-millisecond, so seeding a demo world with
  hundreds of real proofs is practical and nothing needs to be faked.
- Dependencies stay at three audited `@noble` packages.
- The agent's *identity* is not hidden from the firewall. That is deliberate and
  documented, not an oversight — see `docs/security.md`.
