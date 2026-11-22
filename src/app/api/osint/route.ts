/**
 * The OSINT proxy.
 *
 * Every third-party lookup goes through here rather than from the browser, for
 * three reasons: provider API keys stay server-side, responses are cached once
 * for all visitors instead of once per visitor, and the address being looked up
 * is validated before we make an outbound request with it.
 *
 * That last point is the important one. An endpoint that fetches a URL built
 * from user input is a server-side request forgery primitive; restricting the
 * input to public IPv4 unicast addresses is what stops this route being used to
 * probe internal hosts or a cloud metadata service.
 */
import { z } from "zod";
import { lookupIp } from "@/lib/atf/osint/index";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const schema = z.object({
  ip: z.string().min(7).max(15),
});

export async function POST(request: Request) {
  try {
    originGuard(request);
    // Tighter than the read endpoints: each miss costs an outbound call.
    await limit(request, "osint", 30);
    const { ip } = await readJson(request, schema);

    // lookupIp validates the address itself and returns an "unavailable"
    // record rather than throwing, so a rejected address is answered
    // consistently instead of leaking which inputs were interesting.
    const intel = await lookupIp(ip);

    return ok({
      ip: intel.ip,
      threat: intel.threat,
      labels: intel.labels,
      live: intel.live,
      fetchedAt: intel.fetchedAt,
      providers: intel.providers.map((p) => ({
        provider: p.provider,
        origin: p.origin,
        threat: p.threat,
        labels: p.labels,
        evidence: p.evidence,
        reference: p.reference ?? null,
        ms: p.ms,
        cached: p.cached,
      })),
    });
  } catch (error) {
    return fail(error);
  }
}
