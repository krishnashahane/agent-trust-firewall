/**
 * The firewall decision path.
 *
 *   open envelope -> verify identity -> spend nonce -> prove capability
 *   -> build context -> score -> apply policy -> write audit record
 *
 * Every step is fail-closed: an error anywhere produces a BLOCK with a stated
 * reason, never a silent pass. The audit record is written for allowed calls
 * too — a firewall that only logs what it stopped cannot answer "what did this
 * agent do before we noticed".
 */
import { verify as verifySchnorr, type SchnorrProof } from "../identity/schnorr.ts";
import { verifyCapability, type MerkleProof } from "../identity/merkle.ts";
import { assess } from "../risk/engine.ts";
import { DEFAULT_RISK_CONFIG, type RiskConfig } from "../risk/config.ts";
import { escalations, explain, hardRuleViolations, verdictFor } from "./policy.ts";
import { linkRecord } from "../audit/chain.ts";
import { summarizeArguments } from "./arguments.ts";
import { digestOf, bytesToHex, random } from "../crypto/primitives.ts";
import type { Store } from "../store/port.ts";
import type {
  Decision,
  ExternalIntel,
  RequestContext,
  TrafficEvent,
} from "../types.ts";

/** What an agent submits, once its outer envelope has been opened. */
export interface InterceptRequest {
  agentId: string;
  tool: string;
  destination: string;
  nonce: string;
  proof: SchnorrProof;
  capabilityProof: MerkleProof;
  /** may contain sealed fields, which ATF cannot read */
  args: Record<string, unknown>;
}

const HISTORY_WINDOW_MS = 30 * 60_000;
const MAX_HISTORY = 200;

/**
 * The digest a proof is bound to. Recomputed from the request as received, so a
 * proof made for a different call cannot be replayed onto this one.
 */
export function requestDigestFor(request: {
  agentId: string;
  tool: string;
  destination: string;
  capabilityProof: { capability: string };
  args: Record<string, unknown>;
}): string {
  return digestOf({
    agentId: request.agentId,
    tool: request.tool,
    destination: request.destination,
    capability: request.capabilityProof.capability,
    args: request.args,
  });
}

export async function decide(
  store: Store,
  request: InterceptRequest,
  opts: {
    config?: RiskConfig;
    now?: number;
    /**
     * Live third-party intelligence about the caller's origin address.
     *
     * Passed in rather than fetched here on purpose: `decide` stays pure of I/O
     * and instant to test, and the caller decides whether waiting on a network
     * lookup is acceptable for that request. Omitted intel scores zero.
     */
    intel?: ExternalIntel;
  } = {},
): Promise<Decision> {
  const config = opts.config ?? DEFAULT_RISK_CONFIG;
  const now = opts.now ?? Date.now();

  const agent = await store.getAgent(request.agentId);
  const requestDigest = requestDigestFor(request);

  const identityProven = agent
    ? verifySchnorr(agent.signingPublicKey, request.proof, request.nonce, requestDigest)
    : false;

  // Spend the nonce whatever the outcome: a challenge offered to an agent is
  // consumed by the attempt, so a failed probe cannot be retried against it.
  const nonceFresh = await store.consumeNonce(request.nonce, request.agentId, now);

  const capabilityProven = agent
    ? verifyCapability(agent.capabilityRoot, request.capabilityProof)
    : false;

  const analysis = summarizeArguments(request.args);
  const history = (
    await store.eventsForAgent(request.agentId, HISTORY_WINDOW_MS, now)
  ).slice(0, MAX_HISTORY);

  const ctx: RequestContext = {
    agentId: request.agentId,
    agent,
    tool: request.tool,
    destination: request.destination,
    claimedCapability: request.capabilityProof.capability,
    capabilityProven,
    identityProven,
    nonceFresh,
    requestDigest,
    argumentSummary: {
      fieldCount: analysis.fieldCount,
      totalBytes: analysis.totalBytes,
      sealedFieldCount: analysis.sealedFieldCount,
      maxEntropy: analysis.maxEntropy,
      descriptorMismatch: analysis.descriptorMismatch,
    },
    inspectableText: analysis.inspectableText,
    timestamp: now,
    history,
    originIp: agent?.originIp,
    externalIntel: opts.intel,
  };

  const violations = hardRuleViolations(ctx);
  const risk = assess(ctx, config);
  const verdict = verdictFor(violations, risk.score, config, risk.contributions);
  const explanation = explain(
    verdict,
    violations,
    risk.contributions[0]?.evidence,
    escalations(risk.contributions),
  );

  const auditId = bytesToHex(random(16));
  const previous = await store.auditHead();
  const record = linkRecord(
    {
      timestamp: now,
      agentId: request.agentId,
      tool: request.tool,
      destination: request.destination,
      verdict,
      score: risk.score,
      requestDigest,
      violations,
    },
    previous,
    auditId,
  );
  await store.appendAudit(record);

  const event: TrafficEvent = {
    id: auditId,
    agentId: request.agentId,
    agentName: agent?.displayName ?? "unknown agent",
    tool: request.tool,
    destination: request.destination,
    verdict,
    score: risk.score,
    band: risk.band,
    topSignals: risk.contributions
      .filter((c) => c.points > 0)
      .slice(0, 3)
      .map((c) => ({ id: c.id, label: c.label, points: c.points })),
    violations,
    explanation,
    signals: Object.fromEntries(risk.contributions.map((c) => [c.id, c.score])),
    ...(capabilityProven ? { capability: request.capabilityProof.capability } : {}),
    sealedFieldCount: analysis.sealedFieldCount,
    intelLabels: opts.intel?.live ? opts.intel.labels : [],
    intelLive: opts.intel?.live === true,
    timestamp: now,
  };
  await store.appendEvent(event);

  return { verdict, risk, violations, explanation, auditId };
}
