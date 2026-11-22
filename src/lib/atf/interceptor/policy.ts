/**
 * Hard rules.
 *
 * The risk score is a judgement. These are not. A revoked key, an unverifiable
 * proof, a replayed challenge or a capability the agent was never granted are
 * failures of the security model itself, and they BLOCK regardless of how
 * favourably everything else scores. A firewall that could be talked out of
 * these by a good reputation would not be a firewall.
 */
import { capabilityCovers } from "../risk/signals/context.ts";
import type {
  PolicyViolation,
  RequestContext,
  SignalContribution,
  Verdict,
} from "../types.ts";
import type { RiskConfig } from "../risk/config.ts";

export function hardRuleViolations(ctx: RequestContext): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  if (!ctx.agent) {
    violations.push({
      rule: "unknown-agent",
      detail: "The caller is not enrolled with the firewall, so there is no key to verify it against.",
    });
    // Nothing further can be checked without an enrolment record.
    return violations;
  }

  if (ctx.agent.revoked) {
    violations.push({
      rule: "revoked-key",
      detail: `This agent's key was revoked${ctx.agent.revocationReason ? `: ${ctx.agent.revocationReason}` : "."}`,
    });
  }

  if (!ctx.identityProven) {
    violations.push({
      rule: "identity-unproven",
      detail: "The proof of key possession did not verify against the enrolled public key.",
    });
  }

  if (!ctx.nonceFresh) {
    violations.push({
      rule: "replayed-challenge",
      detail: "The challenge used in this proof was already spent, expired, or issued to a different agent — the signature of a replay attack.",
    });
  }

  if (!ctx.capabilityProven) {
    violations.push({
      rule: "capability-unproven",
      detail: `The agent could not prove that "${ctx.claimedCapability}" is in its granted capability set.`,
    });
  } else if (!capabilityCovers(ctx.claimedCapability, ctx.tool)) {
    violations.push({
      rule: "capability-escalation",
      detail: `The agent proved it holds "${ctx.claimedCapability}", which does not authorise calling ${ctx.tool}.`,
    });
  }

  return violations;
}

/**
 * Signals that force at least a FLAG no matter how the weighted score lands.
 *
 * A confident payload detection — text engineered to hijack a downstream model,
 * or a credential riding out in an argument — must never be silently allowed
 * just because it came from a well-behaved agent with a light payload weight.
 * These escalate rather than block outright, because they are heuristics and
 * heuristics produce false positives; a human should see them, not lose them.
 */
const ESCALATION_FLOOR = 0.75;
const ESCALATING_SIGNALS = new Set(["payload"]);

export function escalations(
  contributions: readonly SignalContribution[],
): SignalContribution[] {
  return contributions.filter(
    (c) => ESCALATING_SIGNALS.has(c.id) && c.score >= ESCALATION_FLOOR,
  );
}

/** Fail-closed: anything not positively allowed is at least flagged. */
export function verdictFor(
  violations: readonly PolicyViolation[],
  score: number,
  config: RiskConfig,
  contributions: readonly SignalContribution[] = [],
): Verdict {
  if (violations.length > 0) return "BLOCK";
  if (score >= config.thresholds.block) return "BLOCK";
  if (score >= config.thresholds.flag) return "FLAG";
  if (escalations(contributions).length > 0) return "FLAG";
  return "ALLOW";
}

export function explain(
  verdict: Verdict,
  violations: readonly PolicyViolation[],
  topEvidence: string | undefined,
  escalated: readonly SignalContribution[] = [],
): string {
  if (violations.length > 0) {
    return `Blocked — ${violations[0]?.detail ?? "a security rule was violated."}`;
  }
  if (verdict === "BLOCK") {
    return `Blocked — the risk score crossed the block threshold. ${topEvidence ?? ""}`.trim();
  }
  if (verdict === "FLAG") {
    // When an escalation is what raised this, say so — the weighted score alone
    // would not explain why an otherwise ordinary call was held back.
    const reason = escalated[0]?.evidence ?? topEvidence;
    return `Flagged for review — ${reason ?? "the request scored above the review threshold."}`;
  }
  return `Allowed — ${topEvidence ?? "nothing about this request stood out."}`;
}
