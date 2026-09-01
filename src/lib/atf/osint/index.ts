/**
 * The OSINT aggregator.
 *
 * Fans out to every provider, merges what came back, and caches the result
 * hard. Caching is not an optimisation here — it is what keeps a demo page that
 * anyone can refresh from burning through free-tier rate limits, and what keeps
 * a slow third party from being felt in the UI. In-flight requests are shared so
 * a burst of concurrent lookups for the same address makes one outbound call,
 * not twenty.
 */
import { PROVIDERS } from "./providers.ts";
import { isPublicIpv4 } from "./net.ts";
import type { ExternalIntel, IpIntel, ProviderResult } from "./types.ts";

/** Long enough to stay well inside free tiers; short enough to stay current. */
const TTL_MS = 30 * 60_000;
/** A failed lookup is retried sooner than a successful one is refreshed. */
const FAILURE_TTL_MS = 2 * 60_000;
const MAX_ENTRIES = 500;

interface CacheEntry {
  value: IpIntel;
  expiresAt: number;
}

declare global {
  var __atfOsintCache: Map<string, CacheEntry> | undefined;
  var __atfOsintInflight: Map<string, Promise<IpIntel>> | undefined;
}

const cache = (globalThis.__atfOsintCache ??= new Map<string, CacheEntry>());
const inflight = (globalThis.__atfOsintInflight ??= new Map<string, Promise<IpIntel>>());

function evictIfNeeded(now: number): void {
  if (cache.size <= MAX_ENTRIES) return;
  for (const [key, entry] of cache) {
    if (entry.expiresAt < now) cache.delete(key);
  }
  while (cache.size > MAX_ENTRIES) {
    const oldest = cache.keys().next();
    if (oldest.done) break;
    cache.delete(oldest.value);
  }
}

function merge(ip: string, results: ProviderResult[], now: number): IpIntel {
  const live = results.some((r) => r.origin === "live" || r.origin === "live-clean");
  // Worst case rather than average: one provider calling an address a Tor exit
  // should not be diluted by three others that simply have nothing on it.
  const threat = results.reduce((max, r) => Math.max(max, r.threat), 0);
  const labels = [...new Set(results.flatMap((r) => r.labels))];

  return {
    ip,
    threat,
    labels,
    providers: results,
    live,
    fetchedAt: now,
    // A lookup where every provider failed is cached only briefly, so an
    // outage does not freeze the picture for half an hour.
    expiresAt: now + (live ? TTL_MS : FAILURE_TTL_MS),
  };
}

/**
 * Look one address up. Never throws: an unroutable or malformed address, or a
 * total provider outage, comes back as an intel record with `live: false`.
 */
export async function lookupIp(ip: string, now = Date.now()): Promise<IpIntel> {
  if (!isPublicIpv4(ip)) {
    return {
      ip,
      threat: 0,
      labels: [],
      providers: [
        {
          provider: "input",
          origin: "unavailable",
          threat: 0,
          labels: [],
          evidence: "Not a public IPv4 address; no external lookup was attempted.",
          ms: 0,
          cached: false,
        },
      ],
      live: false,
      fetchedAt: now,
      expiresAt: now + FAILURE_TTL_MS,
    };
  }

  const cached = cache.get(ip);
  if (cached && cached.expiresAt > now) {
    return {
      ...cached.value,
      providers: cached.value.providers.map((p) => ({ ...p, cached: true })),
    };
  }

  const pending = inflight.get(ip);
  if (pending) return pending;

  const work = (async () => {
    // allSettled, not all: one provider throwing must not lose the others.
    const settled = await Promise.allSettled(PROVIDERS.map((provider) => provider(ip)));
    const results: ProviderResult[] = settled.map((outcome, index) =>
      outcome.status === "fulfilled"
        ? outcome.value
        : {
            provider: `provider-${index}`,
            origin: "unavailable" as const,
            threat: 0,
            labels: [],
            evidence: "Provider raised an unexpected error.",
            ms: 0,
            cached: false,
          },
    );
    const merged = merge(ip, results, Date.now());
    cache.set(ip, { value: merged, expiresAt: merged.expiresAt });
    evictIfNeeded(Date.now());
    return merged;
  })().finally(() => {
    inflight.delete(ip);
  });

  inflight.set(ip, work);
  return work;
}

/** Condense an intel record into the small shape the risk engine consumes. */
export function toExternalIntel(intel: IpIntel): ExternalIntel {
  const notable = intel.providers.filter((p) => p.origin === "live" && p.threat > 0);
  const summary =
    notable.length > 0
      ? notable
          .sort((a, b) => b.threat - a.threat)
          .slice(0, 2)
          .map((p) => p.evidence)
          .join(" ")
      : intel.live
        ? `External threat intelligence has nothing on ${intel.ip}.`
        : `No external threat intelligence was available for ${intel.ip}.`;

  return {
    ip: intel.ip,
    threat: intel.threat,
    labels: intel.labels,
    summary,
    live: intel.live,
  };
}

/**
 * Cache-only read. Never touches the network.
 *
 * The agents list renders on every poll, and blocking that render on a dozen
 * outbound lookups put third-party latency directly into our own cold-start
 * path — which is how a page that only lists agents ended up able to time out.
 * Callers on a request path use this and accept that intel arrives a moment
 * later, once `warmIp` has filled the cache.
 */
export function peekIp(ip: string, now = Date.now()): IpIntel | null {
  const entry = cache.get(ip);
  if (!entry || entry.expiresAt <= now) return null;
  return {
    ...entry.value,
    providers: entry.value.providers.map((p) => ({ ...p, cached: true })),
  };
}

/**
 * Fill the cache in the background. Deliberately fire-and-forget: the caller
 * must not await it, and a provider failure must not surface as a rejected
 * promise on a request that had nothing to do with it.
 */
export function warmIp(ip: string): void {
  if (peekIp(ip) || inflight.has(ip)) return;
  void lookupIp(ip).catch(() => {
    // Swallowed by design — lookupIp already records failure as "unavailable",
    // and an unhandled rejection here would take down the whole instance.
  });
}

/** Test seam: drop everything so a test starts from a known state. */
export function resetOsintCache(): void {
  cache.clear();
  inflight.clear();
}

export { isPublicIpv4 } from "./net.ts";
export type { ExternalIntel, IpIntel, ProviderResult } from "./types.ts";
