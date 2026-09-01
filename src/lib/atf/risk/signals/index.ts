import { behaviorSignal } from "./behavior.ts";
import { contextSignal } from "./context.ts";
import { identitySignal } from "./identity.ts";
import { intelSignal } from "./intel.ts";
import { payloadSignal } from "./payload.ts";
import { rateSignal } from "./rate.ts";
import { reputationSignal } from "./reputation.ts";
import type { RequestContext, SignalResult } from "../../types.ts";

export type Signal = (ctx: RequestContext) => SignalResult;

/** Registry of every scoring dimension. Adding a signal is adding one entry. */
export const SIGNALS: readonly Signal[] = [
  identitySignal,
  contextSignal,
  behaviorSignal,
  rateSignal,
  payloadSignal,
  reputationSignal,
  intelSignal,
];

export {
  behaviorSignal,
  contextSignal,
  identitySignal,
  intelSignal,
  payloadSignal,
  rateSignal,
  reputationSignal,
};
export { capabilityCovers, toolSensitivity } from "./context.ts";
