/**
 * Request context.
 *
 * Does the authority the agent presented actually cover the thing it is trying
 * to do, and how much damage would this call do if the agent were compromised?
 * A read-only weather lookup and a wire transfer deserve different scrutiny even
 * when both are perfectly authenticated.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

/** How much blast radius a tool namespace carries, 0-1. */
const SENSITIVITY: Record<string, number> = {
  payments: 1,
  transfers: 1,
  identity: 0.9,
  credentials: 0.95,
  code: 0.9,
  exec: 0.95,
  admin: 0.9,
  email: 0.6,
  calendar: 0.4,
  storage: 0.6,
  search: 0.2,
  weather: 0.05,
};

export function toolSensitivity(tool: string): number {
  const namespace = tool.split(/[.:/]/)[0]?.toLowerCase() ?? "";
  const direct = SENSITIVITY[namespace];
  if (direct !== undefined) return direct;
  // Unknown namespaces are treated as moderately sensitive: default-deny
  // thinking means an unrecognised capability is not assumed harmless.
  return 0.5;
}

/** "payments:transfer" covers tool "payments.transfer"; "payments:*" covers all. */
export function capabilityCovers(capability: string, tool: string): boolean {
  const [capNs, capAction] = capability.split(":");
  if (!capNs) return false;
  const parts = tool.split(/[.:/]/);
  const toolNs = parts[0];
  const toolAction = parts.slice(1).join(".");
  if (capNs !== toolNs) return false;
  if (!capAction || capAction === "*") return true;
  return capAction === toolAction;
}

export function contextSignal(ctx: RequestContext): SignalResult {
  const sensitivity = toolSensitivity(ctx.tool);
  const covers = capabilityCovers(ctx.claimedCapability, ctx.tool);

  // An oversized argument payload on a sensitive tool is the shape of
  // exfiltration; on a search tool it is unremarkable.
  const bulk = Math.min(1, ctx.argumentSummary.totalBytes / 64_000);

  const score = Math.min(
    1,
    (covers ? 0 : 0.8) + sensitivity * 0.35 + bulk * sensitivity * 0.4,
  );

  const notes: string[] = [];
  if (!covers) {
    notes.push(
      `the capability it presented (${ctx.claimedCapability}) does not cover ${ctx.tool}`,
    );
  }
  if (sensitivity >= 0.8) notes.push(`${ctx.tool} is a high-impact action`);
  if (bulk > 0.4) notes.push(`the request carries an unusually large payload (${ctx.argumentSummary.totalBytes} bytes)`);

  return {
    id: "context",
    label: "Request context",
    score,
    evidence:
      notes.length === 0
        ? `${ctx.tool} is within the capability presented and carries a normal payload.`
        : `This call is notable because ${notes.join(", ")}.`,
  };
}
