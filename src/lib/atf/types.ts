/** Shared domain types. Kept free of framework and crypto imports. */
import type { ExternalIntel, IpIntel } from "./osint/types.ts";

export type { ExternalIntel, IpIntel };

export type Verdict = "ALLOW" | "FLAG" | "BLOCK";

export type RiskBand = "minimal" | "low" | "elevated" | "high" | "critical";

export interface AgentRecord {
  agentId: string;
  displayName: string;
  /** ed25519 point — verifies Schnorr proofs of possession */
  signingPublicKey: string;
  /** X25519 point — recipients seal envelopes to this */
  encryptionPublicKey: string;
  /** Merkle root over the granted capability set */
  capabilityRoot: string;
  registeredAt: number;
  keyRotatedAt: number;
  /** public IPv4 this agent calls from, used for external enrichment */
  originIp?: string;
  revoked: boolean;
  revocationReason?: string;
}

/** Everything the risk engine is allowed to see about one call. */
export interface RequestContext {
  agentId: string;
  agent: AgentRecord | null;
  /** the tool being invoked, e.g. "payments.transfer" */
  tool: string;
  /** logical destination, e.g. "api.stripe.com" */
  destination: string;
  /** capability the agent disclosed for this call */
  claimedCapability: string;
  capabilityProven: boolean;
  identityProven: boolean;
  nonceFresh: boolean;
  /** digest of the full request — what the proof is bound to */
  requestDigest: string;
  /** argument metadata; sealed fields contribute descriptors, not values */
  argumentSummary: ArgumentSummary;
  /** plain-text arguments ATF was permitted to read, for injection scanning */
  inspectableText: string;
  timestamp: number;
  /** prior calls by this agent, newest first, used for baseline comparison */
  history: TrafficEvent[];
  /** the public IP this agent is calling from, when the deployment knows it */
  originIp?: string;
  /**
   * What public threat intelligence says about `originIp`. Absent whenever the
   * lookup was skipped, failed, or is still warming — the engine must score
   * correctly without it, so nothing downstream may treat it as required.
   */
  externalIntel?: ExternalIntel;
}

export interface ArgumentSummary {
  fieldCount: number;
  totalBytes: number;
  sealedFieldCount: number;
  /** max Shannon entropy across fields (0-8) */
  maxEntropy: number;
  /** true if any sealed field's descriptor failed verification */
  descriptorMismatch: boolean;
}

export interface SignalResult {
  id: string;
  label: string;
  /** 0-1, how anomalous this dimension is */
  score: number;
  /** plain-language reason a non-specialist can read */
  evidence: string;
}

export interface SignalContribution extends SignalResult {
  weight: number;
  /** points this signal added to the final 0-100 score */
  points: number;
}

export interface RiskAssessment {
  /** 0-100, higher is more dangerous */
  score: number;
  band: RiskBand;
  contributions: SignalContribution[];
}

export interface PolicyViolation {
  rule: string;
  detail: string;
}

export interface Decision {
  verdict: Verdict;
  risk: RiskAssessment;
  /** hard-rule failures; any of these forces BLOCK regardless of score */
  violations: PolicyViolation[];
  /** one sentence a human can act on */
  explanation: string;
  auditId: string;
}

export interface TrafficEvent {
  id: string;
  agentId: string;
  agentName: string;
  tool: string;
  destination: string;
  verdict: Verdict;
  score: number;
  band: RiskBand;
  topSignals: { id: string; label: string; points: number }[];
  violations: PolicyViolation[];
  explanation: string;
  sealedFieldCount: number;
  /** each signal's 0-1 reading, so the tuning preview can re-weigh the call */
  signals?: Record<string, number>;
  /** the capability this call proved, when its Merkle proof verified */
  capability?: string;
  /** threat labels from live external intel, empty when none applied */
  intelLabels: string[];
  /** true when this verdict was informed by a live third-party lookup */
  intelLive: boolean;
  timestamp: number;
}
