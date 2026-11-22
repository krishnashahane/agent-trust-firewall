import { getGateway } from "@/lib/atf/gateway";
import { verifyChain } from "@/lib/atf/audit/chain";
import { adminConfigured, fail, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Reports posture, never secrets. */
export async function GET(request: Request) {
  try {
    limit(request, "health", 60);
    const gateway = await getGateway();
    const audit = await gateway.store.listAudit(2000);
    const auditLength = await gateway.store.auditLength();
    const chain = verifyChain(audit, { window: auditLength > audit.length });
    const agents = await gateway.store.listAgents();

    return ok({
      status: "ok",
      bootedAt: gateway.bootedAt,
      uptimeMs: Date.now() - gateway.bootedAt,
      agentsEnrolled: agents.length,
      auditLength,
      auditChainValid: chain.valid,
      storage:
        gateway.storage === "postgres"
          ? "postgres (durable across restarts)"
          : "in-process (resets on cold start)",
      gatewayKeyPinned: Boolean(process.env.ATF_GATEWAY_SECRET_KEY),
      enrolmentEnabled: adminConfigured(),
    });
  } catch (error) {
    return fail(error);
  }
}
