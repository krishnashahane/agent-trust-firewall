import { riskConfigSchema } from "@/lib/atf/risk/config";
import { verdictFor } from "@/lib/atf/interceptor/policy";
import { getSeededGateway } from "@/lib/atf/gateway";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Re-score recent traffic against a proposed config without committing it, so
 * an operator can see what a threshold change would have done before it does it.
 * Scores are already recorded per event; only the thresholds are re-applied.
 */
export async function POST(request: Request) {
  try {
    originGuard(request);
    await limit(request, "config-preview", 120);
    const config = await readJson(request, riskConfigSchema);
    const gateway = await getSeededGateway();
    const events = await gateway.store.listEvents(200);

    let allowed = 0;
    let flagged = 0;
    let blocked = 0;
    let changed = 0;

    for (const event of events) {
      // Hard-rule blocks are not tunable, so they carry over untouched.
      const verdict =
        event.violations.length > 0
          ? "BLOCK"
          : verdictFor([], event.score, config);
      if (verdict !== event.verdict) changed++;
      if (verdict === "ALLOW") allowed++;
      else if (verdict === "FLAG") flagged++;
      else blocked++;
    }

    return ok({ sampled: events.length, allowed, flagged, blocked, changed });
  } catch (error) {
    return fail(error);
  }
}
