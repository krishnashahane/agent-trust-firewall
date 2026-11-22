import { cookies } from "next/headers";
import { getGateway } from "@/lib/atf/gateway";
import { riskConfigSchema, DEFAULT_RISK_CONFIG } from "@/lib/atf/risk/config";
import {
  SESSION_COOKIE,
  clearSessionConfig,
  configFor,
  hasSandbox,
  isValidSessionId,
  newSessionId,
  setSessionConfig,
} from "@/lib/atf/session";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Risk configuration.
 *
 * Reads and writes are scoped to the caller's own sandbox. The shared gateway
 * config is never mutated by a request — that was the original design and it
 * let any anonymous visitor change the scoring every other visitor saw.
 *
 * What is *not* tunable, in any sandbox, is unchanged: a revoked key, an
 * unverified proof, a replayed challenge or an ungranted capability still
 * BLOCK at every configuration. Sandboxing moves judgement calls, not rules.
 */
export async function GET(request: Request) {
  try {
    await limit(request, "config-get", 120);
    const jar = await cookies();
    const sessionId = jar.get(SESSION_COOKIE)?.value;

    return ok({
      config: configFor(sessionId),
      /** true once this visitor has applied their own settings */
      sandboxed: hasSandbox(sessionId),
      defaults: DEFAULT_RISK_CONFIG,
    });
  } catch (error) {
    return fail(error);
  }
}

export async function PUT(request: Request) {
  try {
    originGuard(request);
    // Tighter than the read path: this is the only write a visitor can make.
    await limit(request, "config-put", 20);
    const config = await readJson(request, riskConfigSchema);

    // Touch the gateway so a cold instance is initialised, but never write to it.
    await getGateway();

    const jar = await cookies();
    const existing = jar.get(SESSION_COOKIE)?.value;
    const sessionId = isValidSessionId(existing) ? existing : newSessionId();
    setSessionConfig(sessionId, config);

    const response = ok({ config, sandboxed: true });
    response.cookies.set({
      name: SESSION_COOKIE,
      value: sessionId,
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60,
    });
    return response;
  } catch (error) {
    return fail(error);
  }
}

/** Drop the sandbox and go back to the shared defaults. */
export async function DELETE(request: Request) {
  try {
    originGuard(request);
    await limit(request, "config-delete", 20);
    const jar = await cookies();
    const sessionId = jar.get(SESSION_COOKIE)?.value;
    if (isValidSessionId(sessionId)) clearSessionConfig(sessionId);
    return ok({ config: DEFAULT_RISK_CONFIG, sandboxed: false });
  } catch (error) {
    return fail(error);
  }
}
