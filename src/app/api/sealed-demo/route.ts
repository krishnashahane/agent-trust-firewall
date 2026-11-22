import { getGateway } from "@/lib/atf/gateway";
import { runSealedFieldDemo } from "@/lib/atf/demo/scenarios";
import { fail, limit, ok, originGuard } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Proof that the end-to-end encryption is load-bearing: a field sealed to a
 * destination key passes through the firewall, is scored, and comes back out
 * still unreadable to ATF.
 */
export async function POST(request: Request) {
  try {
    originGuard(request);
    await limit(request, "sealed-demo", 20);
    const gateway = await getGateway();
    return ok(await runSealedFieldDemo(gateway));
  } catch (error) {
    return fail(error);
  }
}
