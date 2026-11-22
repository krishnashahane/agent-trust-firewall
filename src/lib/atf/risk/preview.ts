/**
 * What a proposed risk config would have done to recorded traffic.
 *
 * Each event carries the seven signal readings it was scored from, so the
 * preview re-weighs them under the proposed weights, re-applies the proposed
 * thresholds, and re-applies escalation floors — exactly the decision path,
 * minus the I/O. At the current config it reproduces every recorded verdict.
 *
 * Hard-rule blocks are not tunable and carry over untouched.
 */
import { weigh } from "./engine.ts";
import { DEFAULT_RISK_CONFIG, type RiskConfig } from "./config.ts";
import { verdictFor } from "../interceptor/policy.ts";
import type { TrafficEvent, Verdict } from "../types.ts";

export interface Preview {
  sampled: number;
  allowed: number;
  flagged: number;
  blocked: number;
  changed: number;
}

export function previewVerdict(event: TrafficEvent, config: RiskConfig): Verdict {
  if (event.violations.length > 0) return "BLOCK";

  if (event.signals) {
    const readings = Object.entries(event.signals).map(([id, score]) => ({ id, score }));
    const { score } = weigh(readings, config);
    return verdictFor([], score, config, readings);
  }

  // Recorded before readings were kept: only thresholds can be re-applied.
  // A FLAG below the default flag threshold can only have come from an
  // escalation floor, which no config change lifts.
  const verdict = verdictFor([], event.score, config);
  const escalated =
    event.verdict === "FLAG" && event.score < DEFAULT_RISK_CONFIG.thresholds.flag;
  return escalated && verdict === "ALLOW" ? "FLAG" : verdict;
}

export function previewTraffic(events: readonly TrafficEvent[], config: RiskConfig): Preview {
  const preview: Preview = { sampled: events.length, allowed: 0, flagged: 0, blocked: 0, changed: 0 };
  for (const event of events) {
    const verdict = previewVerdict(event, config);
    if (verdict !== event.verdict) preview.changed++;
    if (verdict === "ALLOW") preview.allowed++;
    else if (verdict === "FLAG") preview.flagged++;
    else preview.blocked++;
  }
  return preview;
}
