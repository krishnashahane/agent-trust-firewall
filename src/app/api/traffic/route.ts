import { getSeededGateway } from "@/lib/atf/gateway";
import { fail, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX = 250;

/** Recent intercepted calls, newest first. */
export async function GET(request: Request) {
  try {
    await limit(request, "traffic", 240);
    const url = new URL(request.url);
    const requested = Number(url.searchParams.get("limit") ?? 100);
    const count = Number.isFinite(requested)
      ? Math.min(MAX, Math.max(1, Math.floor(requested)))
      : 100;

    const gateway = await getSeededGateway();
    const events = await gateway.store.listEvents(count);
    // Summarise the window actually returned rather than a fixed hour. With a
    // durable store the seeded history ages past any fixed cutoff, and a
    // console that reads zero on a quiet day would be describing the clock,
    // not the firewall.
    const window = events;

    return ok({
      events,
      summary: {
        total: window.length,
        allowed: window.filter((e) => e.verdict === "ALLOW").length,
        flagged: window.filter((e) => e.verdict === "FLAG").length,
        blocked: window.filter((e) => e.verdict === "BLOCK").length,
        sealedFields: window.reduce((s, e) => s + e.sealedFieldCount, 0),
      },
    });
  } catch (error) {
    return fail(error);
  }
}
