/**
 * OSINT enrichment types.
 *
 * The firewall's internal signals only know what this deployment has seen. An
 * agent calling from infrastructure that the wider internet already knows to be
 * hostile — a Tor exit, a scanner, a host with published CVEs — is information
 * the engine cannot derive on its own. This layer fetches that from real public
 * threat-intel sources.
 *
 * The cardinal rule: enrichment is *additive and optional*. Every provider can
 * fail, time out, or be rate-limited, and when that happens the engine must fall
 * back to its internal judgement rather than break. Which of those two happened
 * is recorded per lookup and shown in the UI, because a security product that
 * quietly presents stale or synthetic data as live intel is worse than one that
 * has none.
 */

/** Where a piece of intel came from, and whether it is real. */
export type IntelOrigin =
  /** a live third-party lookup that returned data */
  | "live"
  /** a live lookup that succeeded and found nothing on this indicator */
  | "live-clean"
  /** the provider failed, timed out, or is not configured; nothing was learned */
  | "unavailable";

export interface ProviderResult {
  provider: string;
  origin: IntelOrigin;
  /** 0-1 contribution to the external threat picture; 0 when unavailable */
  threat: number;
  /** short machine-ish labels: "tor", "scanner", "cve", … */
  labels: string[];
  /** one plain-language sentence describing what this provider found */
  evidence: string;
  /** a link a human can open to check the claim themselves */
  reference?: string;
  /** how long the answer took, for the UI's honesty panel */
  ms: number;
  /** true when this result was served from cache rather than a fresh call */
  cached: boolean;
}

export interface IpIntel {
  ip: string;
  /** worst-case threat across providers, 0-1 */
  threat: number;
  /** union of every provider's labels, de-duplicated */
  labels: string[];
  providers: ProviderResult[];
  /** true when at least one provider returned real data */
  live: boolean;
  fetchedAt: number;
  /** ms until this entry is considered stale */
  expiresAt: number;
}

/** What the risk engine consumes. Deliberately small and provider-agnostic. */
export interface ExternalIntel {
  ip: string;
  threat: number;
  labels: string[];
  /** plain-language, already assembled for display in a verdict explanation */
  summary: string;
  live: boolean;
}
