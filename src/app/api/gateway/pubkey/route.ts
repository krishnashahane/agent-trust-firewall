import { gatewayPublicKey } from "@/lib/atf/gateway";
import { fail, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The public half of the gateway's X25519 key. Agents seal envelopes to it. */
export async function GET(request: Request) {
  try {
    limit(request, "pubkey", 120);
    return ok({ publicKey: await gatewayPublicKey(), algorithm: "X25519" });
  } catch (error) {
    return fail(error);
  }
}
