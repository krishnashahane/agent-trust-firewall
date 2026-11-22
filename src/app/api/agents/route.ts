import { getSeededGateway } from "@/lib/atf/gateway";
import { peekIp, warmIp } from "@/lib/atf/osint/index";
import { fail, limit, ok } from "@/lib/guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The enrolled fleet, with the trust picture the dashboard renders. */
export async function GET(request: Request) {
  try {
    await limit(request, "agents", 120);
    const gateway = await getSeededGateway();
    const agents = await gateway.store.listAgents();
    const now = Date.now();

    const rows = await Promise.all(
      agents.map(async (agent) => {
        // A day, not an hour: the persisted history is what gives the trend
        // line and the trust score something to describe.
        const history = await gateway.store.eventsForAgent(agent.agentId, 24 * 60 * 60_000, now);
        const blocked = history.filter((e) => e.verdict === "BLOCK").length;
        const flagged = history.filter((e) => e.verdict === "FLAG").length;
        const avgScore =
          history.length > 0
            ? history.reduce((s, e) => s + e.score, 0) / history.length
            : 0;

        // Enrichment is read from cache only and warmed in the background.
        // Awaiting the lookups here put up to a dozen third-party round-trips
        // into this route's cold path, which is what let a simple list request
        // time out under concurrent navigation. Intel appears on the next poll.
        if (agent.originIp) warmIp(agent.originIp);
        const intel = agent.originIp ? peekIp(agent.originIp) : null;

        return {
          agentId: agent.agentId,
          originIp: agent.originIp ?? null,
          intel: intel
            ? {
                live: intel.live,
                threat: intel.threat,
                labels: intel.labels,
                providers: intel.providers.map((p) => ({
                  provider: p.provider,
                  origin: p.origin,
                  evidence: p.evidence,
                  reference: p.reference ?? null,
                })),
              }
            : null,
          displayName: agent.displayName,
          // The firewall holds only the capability root. What it can show is
          // what this agent has proved, one capability per verified call.
          provedCapabilities: [
            ...new Set(history.flatMap((e) => (e.capability ? [e.capability] : []))),
          ].sort(),
          capabilityRoot: agent.capabilityRoot,
          registeredAt: agent.registeredAt,
          keyRotatedAt: agent.keyRotatedAt,
          revoked: agent.revoked,
          revocationReason: agent.revocationReason ?? null,
          calls: history.length,
          blocked,
          flagged,
          // Trust is the inverse of recent risk: high score, low trust.
          trustScore: Math.round(
            Math.max(0, 100 - avgScore) * (agent.revoked ? 0 : 1),
          ),
          recent: history.slice(0, 24).map((e) => ({ verdict: e.verdict, score: e.score })),
        };
      }),
    );

    return ok({ agents: rows });
  } catch (error) {
    return fail(error);
  }
}
