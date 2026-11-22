import { riskConfigSchema } from "@/lib/atf/risk/config";
import { previewTraffic } from "@/lib/atf/risk/preview";
import { getSeededGateway } from "@/lib/atf/gateway";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Re-score recent traffic against a proposed config without committing it, so
 * an operator can see what a weight or threshold change would have done before
 * it does it.
 */
export async function POST(request: Request) {
  try {
    originGuard(request);
    await limit(request, "config-preview", 120);
    const config = await readJson(request, riskConfigSchema);
    const gateway = await getSeededGateway();
    return ok(previewTraffic(await gateway.store.listEvents(200), config));
  } catch (error) {
    return fail(error);
  }
}
