import { getSeededGateway } from "@/lib/atf/gateway";
import { fail, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The hash-chained log. Digests and metadata only — never argument values. */
export async function GET(request: Request) {
  try {
    await limit(request, "audit", 120);
    const gateway = await getSeededGateway();
    const records = await gateway.store.listAudit(200);
    return ok({
      records: records.slice().reverse(),
      length: await gateway.store.auditLength(),
      durable: gateway.storage === "postgres",
    });
  } catch (error) {
    return fail(error);
  }
}
