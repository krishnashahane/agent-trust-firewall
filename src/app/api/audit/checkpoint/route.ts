import { getSeededGateway } from "@/lib/atf/gateway";
import { signCheckpoint } from "@/lib/atf/audit/checkpoint";
import { fail, HttpError, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * A signed fingerprint of the log as it stands right now. Save it anywhere you
 * control; checking it later with /api/audit/verify?seq=…&hash=… shows whether
 * history before that point was rewritten.
 */
export async function GET(request: Request) {
  try {
    limit(request, "audit-checkpoint", 30);
    const gateway = await getSeededGateway();
    const head = await gateway.store.auditHead();
    if (!head) throw new HttpError(404, "The log has no records yet.");
    return ok(signCheckpoint(head, gateway.secretKey));
  } catch (error) {
    return fail(error);
  }
}
