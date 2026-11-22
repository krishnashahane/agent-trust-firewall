/**
 * Identity posture.
 *
 * Not "did the proof verify" — that is a hard rule, handled by policy. This
 * signal grades the *quality* of the identity behind a verified call: a key
 * enrolled minutes ago, or one that has not been rotated in a very long time,
 * are both worth a second look even when today's proof is mathematically valid.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export function identitySignal(ctx: RequestContext): SignalResult {
  const agent = ctx.agent;
  if (!agent) {
    return {
      id: "identity",
      label: "Identity posture",
      score: 1,
      evidence: "This agent is not enrolled with the firewall — no key on record to check against.",
    };
  }
  if (agent.revoked) {
    return {
      id: "identity",
      label: "Identity posture",
      score: 1,
      evidence: `This agent's key was revoked${agent.revocationReason ? ` (${agent.revocationReason})` : ""}.`,
    };
  }

  const ageMs = Math.max(0, ctx.timestamp - agent.registeredAt);
  const sinceRotation = Math.max(0, ctx.timestamp - agent.keyRotatedAt);

  // Very new enrolments are unproven; very stale keys have had a long window in
  // which to leak. Both bend the score up, from opposite ends.
  const newness = ageMs < HOUR ? 0.5 * (1 - ageMs / HOUR) : 0;
  const staleness = sinceRotation > 90 * DAY ? Math.min(0.5, (sinceRotation - 90 * DAY) / (270 * DAY)) : 0;
  const unproven = ctx.identityProven ? 0 : 1;

  const score = Math.min(1, Math.max(unproven, newness + staleness));

  const notes: string[] = [];
  if (!ctx.identityProven) notes.push("its proof of key possession did not verify");
  if (newness > 0.1) notes.push(`it was enrolled only ${Math.round(ageMs / 60_000)} minutes ago`);
  if (staleness > 0.05) notes.push(`its key has not been rotated in ${Math.round(sinceRotation / DAY)} days`);

  return {
    id: "identity",
    label: "Identity posture",
    score,
    evidence:
      notes.length === 0
        ? "Established key, proof verified, no rotation concerns."
        : `Identity concern: ${notes.join("; ")}.`,
  };
}
