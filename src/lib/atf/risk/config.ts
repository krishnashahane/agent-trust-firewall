/**
 * Scoring configuration as data.
 *
 * Weights and thresholds live here rather than being baked into the engine, so
 * an operator can retune the firewall without a redeploy — and so the dashboard
 * can re-score a window of live traffic against a proposed config and show the
 * effect before anyone commits to it.
 */
import { z } from "zod";

export const riskConfigSchema = z.object({
  weights: z.object({
    identity: z.number().min(0).max(1),
    context: z.number().min(0).max(1),
    behavior: z.number().min(0).max(1),
    rate: z.number().min(0).max(1),
    payload: z.number().min(0).max(1),
    reputation: z.number().min(0).max(1),
    intel: z.number().min(0).max(1),
  }),
  thresholds: z
    .object({
      /** at or above this score a call is flagged for review */
      flag: z.number().min(0).max(100),
      /** at or above this score a call is blocked outright */
      block: z.number().min(0).max(100),
    })
    .refine((t) => t.flag <= t.block, {
      message: "flag threshold must not exceed block threshold",
    }),
});

export type RiskConfig = z.infer<typeof riskConfigSchema>;

/**
 * Defaults. Identity and context carry the most weight because they are the
 * questions a firewall exists to ask; reputation is deliberately light so a
 * well-behaved history can never fully offset a dangerous request, and external
 * intel is lighter still because it describes an address rather than a caller.
 */
export const DEFAULT_RISK_CONFIG: RiskConfig = {
  weights: {
    identity: 0.3,
    context: 0.25,
    behavior: 0.15,
    rate: 0.1,
    payload: 0.15,
    reputation: 0.05,
    // External intel is weighted below identity and context deliberately: it is
    // contextual evidence about an address, not proof about this caller.
    intel: 0.12,
  },
  thresholds: { flag: 45, block: 70 },
};

export const BANDS = [
  { band: "minimal", max: 20 },
  { band: "low", max: 40 },
  { band: "elevated", max: 60 },
  { band: "high", max: 80 },
  { band: "critical", max: 100 },
] as const;
