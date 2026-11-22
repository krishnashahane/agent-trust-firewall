import { getGateway } from "@/lib/atf/gateway";
import { DuplicateAgentError, registerAgent, registrationSchema } from "@/lib/atf/identity/registry";
import { fail, HttpError, limit, ok, originGuard, readJson, requireAdmin } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    originGuard(request);
    await limit(request, "register", 10);
    // Before the body is read: an unauthenticated caller costs nothing more.
    requireAdmin(request);
    const input = await readJson(request, registrationSchema);
    const gateway = await getGateway();
    const agent = await registerAgent(gateway.store, input);

    // Public record only: no secret was submitted and none is returned.
    return ok(
      {
        agentId: agent.agentId,
        displayName: agent.displayName,
        capabilityRoot: agent.capabilityRoot,
        registeredAt: agent.registeredAt,
      },
      201,
    );
  } catch (error) {
    if (error instanceof DuplicateAgentError) {
      return fail(new HttpError(409, "That agent id is already enrolled."));
    }
    return fail(error);
  }
}
