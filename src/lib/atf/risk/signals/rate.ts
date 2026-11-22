/**
 * Rate anomaly.
 *
 * Two things matter and they are different: sustained volume (a scraper) and
 * sudden burst (a hijacked agent draining an API before anyone notices). We
 * measure the sustained rate over a one-minute window, and compare the last ten
 * seconds against the agent's pace *before* that minute.
 *
 * Comparing against the current minute was a bug: a flood is most of that
 * minute, so it raised its own baseline and hid itself. Measured against the
 * agent's earlier history, 40 calls in 10 seconds from an agent that normally
 * makes one a minute reads as the burst it is.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

const WINDOW_MS = 60_000;
const BURST_MS = 10_000;
/** calls per minute at which sustained volume alone is fully anomalous */
const SATURATION_RPM = 120;
/** fewer calls than this in the burst window is not a burst, whatever the ratio */
const MIN_BURST = 5;

export function rateSignal(ctx: RequestContext): SignalResult {
  const recent = ctx.history.filter((e) => ctx.timestamp - e.timestamp <= WINDOW_MS);
  const burst = recent.filter((e) => ctx.timestamp - e.timestamp <= BURST_MS);
  const earlier = ctx.history.filter((e) => ctx.timestamp - e.timestamp > WINDOW_MS);

  const perMinute = recent.length + 1;
  const sustained = Math.min(1, perMinute / SATURATION_RPM);

  // Burst factor: how much busier the last 10s is than this agent's usual
  // pace before the current minute. The floor on `expected` and the MIN_BURST
  // gate matter — without them a single call into an empty window divides by
  // almost nothing and reads as a flood.
  const burstCount = burst.length + 1;
  const oldest = earlier.reduce((min, e) => Math.min(min, e.timestamp), ctx.timestamp - WINDOW_MS);
  const spanMs = Math.max(WINDOW_MS, ctx.timestamp - WINDOW_MS - oldest);
  const expectedInBurst = Math.max(1, (earlier.length * BURST_MS) / spanMs);
  const burstRatio = burstCount / expectedInBurst;
  const spike =
    burstCount < MIN_BURST ? 0 : Math.min(1, Math.max(0, (burstRatio - 1.5) / 4));

  const score = Math.min(1, Math.max(sustained, spike * 0.9));

  let evidence: string;
  if (score < 0.15) {
    evidence = `Normal pace — ${perMinute} call${perMinute === 1 ? "" : "s"} in the last minute.`;
  } else if (spike > sustained) {
    evidence = `Sudden burst — ${burst.length + 1} calls in 10 seconds, well above this agent's own recent pace.`;
  } else {
    evidence = `High sustained volume — ${perMinute} calls in the last minute.`;
  }

  return { id: "rate", label: "Request rate", score, evidence };
}
