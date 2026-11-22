/**
 * Behavioural deviation.
 *
 * A compromised agent still holds valid credentials — what gives it away is that
 * it starts doing things this agent has never done. We compare the call against
 * the agent's own history on three axes: has it used this tool before, has it
 * talked to this destination before, and is it operating at an hour it normally
 * doesn't. A brand-new agent has no baseline, which is itself mildly notable —
 * scored as uncertainty, not as guilt.
 *
 * Only calls the firewall *allowed* count as the agent's habits. Learning from
 * blocked or flagged attempts would let an attacker retry a refused destination
 * until it looked normal.
 *
 * A first contact matters most when the action moves data or money: a sync
 * agent writing a full export to a host it has never used is the shape of
 * exfiltration, and scores high enough to be held for review.
 */
import type { RequestContext, SignalResult } from "../../types.ts";
import { toolSensitivity } from "./context.ts";

const WRITE_LIKE = /(write|put|post|send|charge|refund|transfer|pay|delete|remove|drop|exec|run|deploy|upload|export|create|update)/i;

/** Actions that move data or money, or are dangerous by namespace. */
export function isSensitiveAction(tool: string): boolean {
  const sensitivity = toolSensitivity(tool);
  const action = tool.split(/[.:/]/).slice(1).join(".");
  return sensitivity >= 0.9 || (sensitivity >= 0.5 && WRITE_LIKE.test(action));
}

/** below this many observations we cannot claim to know the agent's habits */
const BASELINE_MIN = 8;

export function behaviorSignal(ctx: RequestContext): SignalResult {
  const history = ctx.history.filter((e) => e.verdict === "ALLOW");
  if (history.length < BASELINE_MIN) {
    return {
      id: "behavior",
      label: "Behaviour baseline",
      score: 0.25,
      evidence: `Only ${history.length} prior call${history.length === 1 ? "" : "s"} on record — not enough history to know what normal looks like for this agent yet.`,
    };
  }

  const tools = new Set(history.map((e) => e.tool));
  const destinations = new Set(history.map((e) => e.destination));
  const hours = new Set(history.map((e) => new Date(e.timestamp).getUTCHours()));
  const hour = new Date(ctx.timestamp).getUTCHours();

  const newTool = !tools.has(ctx.tool);
  const newDestination = !destinations.has(ctx.destination);
  const oddHour = !hours.has(hour) && hours.size >= 4;
  const sensitive = isSensitiveAction(ctx.tool);

  const score = Math.min(
    1,
    (newTool ? 0.55 : 0) +
      (newDestination ? (sensitive ? 0.65 : 0.35) : 0) +
      (oddHour ? 0.2 : 0),
  );

  const notes: string[] = [];
  if (newTool) notes.push(`has never called ${ctx.tool} before`);
  if (newDestination) {
    notes.push(
      `has never contacted ${ctx.destination} before${
        sensitive ? `, and ${ctx.tool} sends, writes or moves something` : ""
      }`,
    );
  }
  if (oddHour) notes.push(`is active at an hour it normally isn't (${hour}:00 UTC)`);

  return {
    id: "behavior",
    label: "Behaviour baseline",
    score,
    evidence:
      notes.length === 0
        ? "Matches this agent's established pattern of tools, destinations and timing."
        : `This agent ${notes.join(", and ")}.`,
  };
}
