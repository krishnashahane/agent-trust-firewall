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

/**
 * Weight signal readings into a 0-100 score. Shared by `assess` and by the
 * tuning preview, which re-scores recorded readings under a proposed config —
 * so a preview at the current config reproduces every recorded score exactly.
 */
export function weigh<T extends { id: string; score: number }>(
  readings: readonly T[],
  config: RiskConfig,
): { score: number; contributions: (T & { weight: number; points: number })[] } {
  const weights = config.weights as Record<string, number | undefined>;
  const totalWeight = readings.reduce((sum, r) => sum + (weights[r.id] ?? 0), 0);
  const contributions = readings.map((reading) => {
    const weight = weights[reading.id] ?? 0;
    // Normalising by total weight keeps the score on a 0-100 scale no matter
    // how an operator has retuned the sliders.
    const points = totalWeight > 0 ? (reading.score * weight * 100) / totalWeight : 0;
    return { ...reading, weight, points: Number(points.toFixed(2)) };
  });
  const score = Math.min(
    100,
    Math.max(0, Number(contributions.reduce((sum, c) => sum + c.points, 0).toFixed(2))),
  );
  return { score, contributions };
}

export function assess(
  ctx: RequestContext,
  config: RiskConfig = DEFAULT_RISK_CONFIG,
): RiskAssessment {
  const results = SIGNALS.map((signal) => signal(ctx));
  const { score, contributions } = weigh(results, config) as {
    score: number;
    contributions: SignalContribution[];
  };

  return {
    score,
    band: bandFor(score),
    contributions: contributions.sort((a, b) => b.points - a.points),
  };
}
