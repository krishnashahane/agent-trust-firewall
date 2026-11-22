import { z } from "zod";
import { getGateway } from "@/lib/atf/gateway";
import { issueChallenge } from "@/lib/atf/identity/nonce";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const schema = z.object({
  agentId: z.string().min(3).max(64).regex(/^[a-z0-9][a-z0-9._-]*$/i),
});

/**
 * Issued to any caller: a challenge is worthless without the secret key it must
 * be answered with, and refusing to issue one to unknown ids would leak which
 * agent ids exist.
 */
export async function POST(request: Request) {
  try {
    originGuard(request);
    await limit(request, "challenge", 120);
    const { agentId } = await readJson(request, schema);
    const gateway = await getGateway();
    const challenge = await issueChallenge(gateway.store, agentId);
    return ok(challenge);
  } catch (error) {
    return fail(error);
  }
}
