/**
 * Reputation.
 *
 * How has this agent behaved recently? An agent whose last twenty calls were all
 * clean earns a little benefit of the doubt; one that has been blocked twice in
 * the last five minutes does not. Reputation decays with time so a single bad
 * afternoon does not follow an agent forever.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

const HALF_LIFE_MS = 10 * 60_000;

export function reputationSignal(ctx: RequestContext): SignalResult {
  const history = ctx.history;
  if (history.length === 0) {
    return {
      id: "reputation",
      label: "Recent reputation",
      score: 0.2,
      evidence: "No history yet — this is the first call ATF has seen from this agent.",
    };
  }

  let weighted = 0;
  let total = 0;
  let blocked = 0;
  for (const event of history) {
    const age = Math.max(0, ctx.timestamp - event.timestamp);
    const decay = Math.pow(0.5, age / HALF_LIFE_MS);
    const penalty = event.verdict === "BLOCK" ? 1 : event.verdict === "FLAG" ? 0.45 : 0;
    weighted += penalty * decay;
    total += decay;
    if (event.verdict === "BLOCK") blocked++;
  }

  const score = total > 0 ? Math.min(1, weighted / total) : 0.2;

  return {
    id: "reputation",
    label: "Recent reputation",
    score,
    evidence:
      score < 0.1
        ? `Clean recent record across ${history.length} call${history.length === 1 ? "" : "s"}.`
        : `${blocked} of this agent's last ${history.length} calls were blocked, weighted towards the most recent.`,
  };
}
