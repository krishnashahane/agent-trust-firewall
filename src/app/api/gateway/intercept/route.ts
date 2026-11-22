/**
 * The firewall endpoint.
 *
 * An agent submits a sealed envelope. ATF opens it inside its trust boundary,
 * runs the decision, and seals the verdict back to the caller so the reply is
 * as confidential as the request. A plaintext submission is also accepted for
 * integrators who terminate encryption elsewhere — but it is scored knowing
 * that, and the response says which path was used rather than implying
 * protection that was not applied.
 */
import { z } from "zod";
import { getGateway } from "@/lib/atf/gateway";
import { decide, type InterceptRequest } from "@/lib/atf/interceptor/decide";
import { issueChallenge } from "@/lib/atf/identity/nonce";
import { EnvelopeError, open, seal } from "@/lib/atf/crypto/e2ee";
import { fail, HttpError, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const hex = (bytes: number) =>
  z.string().length(bytes * 2).regex(/^[0-9a-f]+$/i);

const signedCallSchema = z.object({
  agentId: z.string().min(3).max(64).regex(/^[a-z0-9][a-z0-9._-]*$/i),
  tool: z.string().min(1).max(128).regex(/^[a-z0-9][a-z0-9._:/-]*$/i),
  destination: z.string().min(1).max(253),
  nonce: hex(32),
  proof: z.object({
    commitment: hex(32),
    response: hex(32),
  }),
  capabilityProof: z.object({
    capability: z.string().min(1).max(64),
    index: z.number().int().min(0).max(1_000_000),
    path: z.array(hex(32)).max(32),
  }),
  args: z.record(z.string(), z.unknown()),
});

const envelopeSchema = z.object({
  v: z.literal(1),
  epk: hex(32),
  nonce: hex(24),
  ct: z.string().min(2).max(700_000).regex(/^[0-9a-f]+$/i),
  aad: z.object({
    agentId: z.string().min(3).max(64),
    requestDigest: hex(32),
    issuedAt: z.number().int(),
  }),
});

/** Any of these means the caller did not prove it is the agent it named. */
const IDENTITY_RULES = new Set([
  "unknown-agent",
  "revoked-key",
  "identity-unproven",
  "replayed-challenge",
]);

const bodySchema = z.union([
  z.object({ envelope: envelopeSchema, replyTo: hex(32).optional() }),
  z.object({ call: signedCallSchema }),
]);

export async function POST(request: Request) {
  try {
    originGuard(request);
    limit(request, "intercept", 120);
    const body = await readJson(request, bodySchema);
    const gateway = await getGateway();

    let call: InterceptRequest;
    let encrypted: boolean;

    if ("envelope" in body) {
      let opened: unknown;
      try {
        opened = open(gateway.secretKey, body.envelope);
      } catch (error) {
        if (error instanceof EnvelopeError) {
          // Uniform response: a probing caller learns nothing about which part
          // of the envelope was wrong.
          throw new HttpError(400, "Envelope could not be opened.");
        }
        throw error;
      }
      const parsed = signedCallSchema.safeParse(opened);
      if (!parsed.success) throw new HttpError(400, "Envelope contents are malformed.");
      // The envelope's claimed sender must match the call it carries, or an
      // attacker could wrap someone else's call under its own identity.
      if (parsed.data.agentId !== body.envelope.aad.agentId) {
        throw new HttpError(400, "Envelope sender does not match the call it carries.");
      }
      call = parsed.data;
      encrypted = true;
    } else {
      call = body.call;
      encrypted = false;
    }

    const decision = await decide(gateway.store, call, { config: gateway.config });

    // The next single-use challenge rides back with the verdict, so an agent
    // in steady state makes one round trip per call instead of two. Only for a
    // caller that just proved it holds the agent's key.
    const nextChallenge = decision.violations.some((v) => IDENTITY_RULES.has(v.rule))
      ? null
      : await issueChallenge(gateway.store, call.agentId);
    const payload = {
      verdict: decision.verdict,
      score: decision.risk.score,
      band: decision.risk.band,
      explanation: decision.explanation,
      violations: decision.violations,
      contributions: decision.risk.contributions,
      auditId: decision.auditId,
      transport: encrypted ? "sealed" : "plaintext",
      nextChallenge,
    };

    // Seal the verdict back when the caller gave us somewhere to seal it to.
    if ("envelope" in body && body.replyTo) {
      return ok({
        sealed: seal(body.replyTo, payload, {
          agentId: call.agentId,
          requestDigest: body.envelope.aad.requestDigest,
          issuedAt: Date.now(),
        }),
        transport: "sealed",
      });
    }

    return ok(payload, decision.verdict === "BLOCK" ? 403 : 200);
  } catch (error) {
    return fail(error);
  }
}
