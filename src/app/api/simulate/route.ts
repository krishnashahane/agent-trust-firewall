import { cookies } from "next/headers";
import { z } from "zod";
import { getGateway } from "@/lib/atf/gateway";
import { runScenario, SCENARIOS } from "@/lib/atf/demo/scenarios";
import { SESSION_COOKIE, configFor } from "@/lib/atf/session";
import { fail, limit, ok, originGuard, readJson } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ids = SCENARIOS.map((s) => s.id) as [string, ...string[]];
const schema = z.object({ scenario: z.enum(ids) });

/** The catalogue, so the UI never hardcodes what the engine supports. */
export async function GET(request: Request) {
  try {
    limit(request, "simulate-list", 120);
    return ok({ scenarios: SCENARIOS });
  } catch (error) {
    return fail(error);
  }
}

/**
 * Run one adversary against the live firewall. The flood scenario makes dozens
 * of real calls, so this is limited more tightly than a read endpoint.
 */
export async function POST(request: Request) {
  try {
    originGuard(request);
    limit(request, "simulate", 20);
    const { scenario } = await readJson(request, schema);
    const gateway = await getGateway();
    // Score against this visitor's sandbox, falling back to the shared
    // read-only defaults when they have not tuned anything.
    const jar = await cookies();
    const config = configFor(jar.get(SESSION_COOKIE)?.value);
    const outcome = await runScenario(
      gateway,
      scenario as Parameters<typeof runScenario>[1],
      config,
    );
    return ok(outcome);
  } catch (error) {
    return fail(error);
  }
}
