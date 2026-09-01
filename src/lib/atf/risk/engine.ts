/**
 * The risk engine.
 *
 * A pure function: the same context and config always produce the same score.
 * That matters twice over — it makes the engine testable, and it means every
 * verdict can be re-derived and audited after the fact.
 *
 * The output is deliberately *explainable*. Every point in the final 0-100 is
 * attributable to a named signal with a sentence of evidence, because "the model
 * said 87" is not something a security operator can act on.
 */
import { SIGNALS } from "./signals/index.ts";
import { BANDS, DEFAULT_RISK_CONFIG, type RiskConfig } from "./config.ts";
import type {
  RequestContext,
  RiskAssessment,
  RiskBand,
  SignalContribution,
} from "../types.ts";

export function bandFor(score: number): RiskBand {
  for (const { band, max } of BANDS) {
    if (score <= max) return band;
  }
  return "critical";
}

export function assess(
  ctx: RequestContext,
  config: RiskConfig = DEFAULT_RISK_CONFIG,
): RiskAssessment {
  const weights = config.weights as Record<string, number | undefined>;

  const results = SIGNALS.map((signal) => signal(ctx));
  const totalWeight = results.reduce((sum, r) => sum + (weights[r.id] ?? 0), 0);

  const contributions: SignalContribution[] = results.map((result) => {
    const weight = weights[result.id] ?? 0;
    // Normalising by total weight keeps the score on a 0-100 scale no matter
    // how an operator has retuned the sliders.
    const points = totalWeight > 0 ? (result.score * weight * 100) / totalWeight : 0;
    return { ...result, weight, points: Number(points.toFixed(2)) };
  });

  const score = Math.min(
    100,
    Math.max(0, Number(contributions.reduce((sum, c) => sum + c.points, 0).toFixed(2))),
  );

  return {
    score,
    band: bandFor(score),
    contributions: contributions.sort((a, b) => b.points - a.points),
  };
}
