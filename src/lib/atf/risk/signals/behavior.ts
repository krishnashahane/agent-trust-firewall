/**
 * Behavioural deviation.
 *
 * A compromised agent still holds valid credentials — what gives it away is that
 * it starts doing things this agent has never done. We compare the call against
 * the agent's own history on three axes: has it used this tool before, has it
 * talked to this destination before, and is it operating at an hour it normally
 * doesn't. A brand-new agent has no baseline, which is itself mildly notable —
 * scored as uncertainty, not as guilt.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

/** below this many observations we cannot claim to know the agent's habits */
const BASELINE_MIN = 8;

export function behaviorSignal(ctx: RequestContext): SignalResult {
  const history = ctx.history;
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

  const score = Math.min(
    1,
    (newTool ? 0.55 : 0) + (newDestination ? 0.35 : 0) + (oddHour ? 0.2 : 0),
  );

  const notes: string[] = [];
  if (newTool) notes.push(`has never called ${ctx.tool} before`);
  if (newDestination) notes.push(`has never contacted ${ctx.destination} before`);
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
