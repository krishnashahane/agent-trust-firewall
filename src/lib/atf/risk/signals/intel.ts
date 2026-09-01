/**
 * External threat intelligence.
 *
 * The other five signals reason about what this deployment has seen. This one
 * reasons about what the rest of the internet already knows: whether the address
 * an agent calls from is a Tor exit, a known scanner, a host with published
 * CVEs, or an address people have filed abuse reports against.
 *
 * It is the only signal fed by data ATF did not generate, which makes its
 * failure modes different from the others. Two rules follow:
 *
 *  1. **Absent intel scores zero, not "clean."** If the lookup did not happen or
 *     every provider was down, this signal contributes nothing and says so. It
 *     must never let an outage read as a good reputation.
 *  2. **It cannot block on its own.** External reputation is contextual, not
 *     authoritative — addresses are shared, recycled and mislabelled. It raises
 *     the score and its evidence names the provider, so a human can check the
 *     claim rather than take it on faith.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

export function intelSignal(ctx: RequestContext): SignalResult {
  const intel = ctx.externalIntel;

  if (!intel) {
    return {
      id: "intel",
      label: "External intel",
      score: 0,
      evidence: ctx.originIp
        ? `No external threat intelligence has been fetched for ${ctx.originIp} yet.`
        : "No origin address is recorded for this agent, so no external lookup applies.",
    };
  }

  if (!intel.live) {
    // Providers were unreachable. Contribute nothing and be explicit about why:
    // silence here must not be mistaken for a clean result.
    return {
      id: "intel",
      label: "External intel",
      score: 0,
      evidence: `External threat intelligence was unavailable for ${intel.ip}, so this signal contributed nothing.`,
    };
  }

  if (intel.threat <= 0) {
    return {
      id: "intel",
      label: "External intel",
      score: 0,
      evidence: intel.summary,
    };
  }

  return {
    id: "intel",
    label: "External intel",
    score: Math.min(1, intel.threat),
    evidence: intel.summary,
  };
}
