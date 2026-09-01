/**
 * One function per threat-intel provider.
 *
 * Each returns a ProviderResult and never throws: a provider that is down must
 * degrade the picture, not the request. Each also distinguishes "I looked and
 * found nothing" (`live-clean` — a real, useful answer) from "I could not look"
 * (`unavailable`), because collapsing those two would let an outage read as a
 * clean bill of health.
 *
 * Only documented public endpoints are used, and the two keyless providers are
 * the ones the deployment relies on; the rest activate when a key is present.
 */
import {
  asNumberArray,
  asRecord,
  asStringArray,
  getJson,
} from "./net.ts";
import type { ProviderResult } from "./types.ts";

const unavailable = (provider: string, why: string, ms: number): ProviderResult => ({
  provider,
  origin: "unavailable",
  threat: 0,
  labels: [],
  evidence: why,
  ms,
  cached: false,
});

/**
 * GreyNoise Community — is this address one of the machines that spends its day
 * scanning the internet, and is that scanning benign or malicious?
 *
 * No API key. A 404 is the documented "not observed" answer, which is a real
 * finding rather than an error.
 */
export async function greynoise(ip: string): Promise<ProviderResult> {
  const started = Date.now();
  try {
    const { status, body } = await getJson(
      `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
    );
    const ms = Date.now() - started;
    const data = asRecord(body);

    if (status === 404 || data["noise"] === false) {
      // Documented "not observed scanning the internet".
      if (data["riot"] === true) {
        return {
          provider: "GreyNoise",
          origin: "live",
          threat: 0,
          labels: ["known-good"],
          evidence: `GreyNoise lists ${ip} as common business infrastructure, not a scanner.`,
          reference: `https://viz.greynoise.io/ip/${ip}`,
          ms,
          cached: false,
        };
      }
      return {
        provider: "GreyNoise",
        origin: "live-clean",
        threat: 0,
        labels: [],
        evidence: `GreyNoise has not observed ${ip} scanning the internet.`,
        reference: `https://viz.greynoise.io/ip/${ip}`,
        ms,
        cached: false,
      };
    }

    if (status !== 200) {
      return unavailable("GreyNoise", `GreyNoise returned HTTP ${status}.`, ms);
    }

    const classification =
      typeof data["classification"] === "string" ? data["classification"] : "unknown";
    const lastSeen = typeof data["last_seen"] === "string" ? data["last_seen"] : null;
    const noise = data["noise"] === true;

    // Malicious classification is the strongest single external signal here;
    // "unknown" scanning traffic is suspicious but not damning.
    const threat =
      classification === "malicious" ? 0.9 : classification === "benign" ? 0.05 : noise ? 0.45 : 0;

    const labels = [
      noise ? "scanner" : null,
      classification === "malicious" ? "malicious" : null,
      classification === "benign" ? "benign-scanner" : null,
    ].filter((l): l is string => l !== null);

    return {
      provider: "GreyNoise",
      origin: "live",
      threat,
      labels,
      evidence: noise
        ? `GreyNoise has observed ${ip} scanning the internet and classifies it as ${classification}${
            lastSeen ? `, last seen ${lastSeen}` : ""
          }.`
        : `GreyNoise classifies ${ip} as ${classification}.`,
      reference: `https://viz.greynoise.io/ip/${ip}`,
      ms,
      cached: false,
    };
  } catch (error) {
    return unavailable(
      "GreyNoise",
      error instanceof Error ? error.message : "lookup failed",
      Date.now() - started,
    );
  }
}

/**
 * Shodan InternetDB — what is exposed on this address, and does it carry
 * published CVEs or notable tags (tor, proxy, compromised)?
 *
 * No API key. "No information available" is a genuine clean result.
 */
export async function shodan(ip: string): Promise<ProviderResult> {
  const started = Date.now();
  try {
    const { status, body } = await getJson(
      `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
    );
    const ms = Date.now() - started;
    const data = asRecord(body);

    if (status === 404 || typeof data["detail"] === "string") {
      return {
        provider: "Shodan InternetDB",
        origin: "live-clean",
        threat: 0,
        labels: [],
        evidence: `Shodan has no exposure record for ${ip}.`,
        reference: `https://www.shodan.io/host/${ip}`,
        ms,
        cached: false,
      };
    }

    if (status !== 200) {
      return unavailable("Shodan InternetDB", `Shodan returned HTTP ${status}.`, ms);
    }

    const ports = asNumberArray(data["ports"]);
    const vulns = asStringArray(data["vulns"]);
    const tags = asStringArray(data["tags"]);
    const hostnames = asStringArray(data["hostnames"]);

    // Anonymising infrastructure and published CVEs are the two findings here
    // that genuinely change how much an agent's origin should be trusted.
    const anonymising = tags.some((t) =>
      ["tor", "proxy", "vpn", "compromised", "malware"].includes(t.toLowerCase()),
    );
    const threat = Math.min(
      1,
      (anonymising ? 0.7 : 0) + Math.min(0.5, vulns.length * 0.12) + (tags.length > 0 ? 0.05 : 0),
    );

    const notes: string[] = [];
    if (tags.length > 0) notes.push(`tagged ${tags.join(", ")}`);
    if (vulns.length > 0) {
      notes.push(
        `${vulns.length} published ${vulns.length === 1 ? "CVE" : "CVEs"} (${vulns.slice(0, 3).join(", ")}${vulns.length > 3 ? "…" : ""})`,
      );
    }
    if (ports.length > 0) notes.push(`${ports.length} open ${ports.length === 1 ? "port" : "ports"}`);
    if (hostnames.length > 0) notes.push(`resolves to ${hostnames[0]}`);

    return {
      provider: "Shodan InternetDB",
      origin: notes.length > 0 ? "live" : "live-clean",
      threat,
      labels: [...tags.map((t) => t.toLowerCase()), vulns.length > 0 ? "cve" : null].filter(
        (l): l is string => l !== null,
      ),
      evidence:
        notes.length > 0
          ? `Shodan sees ${ip} ${notes.join("; ")}.`
          : `Shodan has nothing notable on ${ip}.`,
      reference: `https://www.shodan.io/host/${ip}`,
      ms,
      cached: false,
    };
  } catch (error) {
    return unavailable(
      "Shodan InternetDB",
      error instanceof Error ? error.message : "lookup failed",
      Date.now() - started,
    );
  }
}

/**
 * AbuseIPDB — how many people have reported this address, and how confident is
 * the aggregate? Requires a free API key; skipped cleanly when unset.
 */
export async function abuseipdb(ip: string): Promise<ProviderResult> {
  const started = Date.now();
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) {
    return unavailable("AbuseIPDB", "No ABUSEIPDB_API_KEY configured.", 0);
  }
  try {
    const { status, body } = await getJson(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: key } },
    );
    const ms = Date.now() - started;
    if (status !== 200) {
      return unavailable("AbuseIPDB", `AbuseIPDB returned HTTP ${status}.`, ms);
    }
    const data = asRecord(asRecord(body)["data"]);
    const confidence =
      typeof data["abuseConfidenceScore"] === "number" ? data["abuseConfidenceScore"] : 0;
    const reports = typeof data["totalReports"] === "number" ? data["totalReports"] : 0;

    return {
      provider: "AbuseIPDB",
      origin: reports > 0 ? "live" : "live-clean",
      threat: Math.min(1, confidence / 100),
      labels: confidence >= 50 ? ["abuse-reported"] : [],
      evidence:
        reports > 0
          ? `AbuseIPDB holds ${reports} report${reports === 1 ? "" : "s"} against ${ip}, ${confidence}% abuse confidence.`
          : `AbuseIPDB has no reports against ${ip}.`,
      reference: `https://www.abuseipdb.com/check/${ip}`,
      ms,
      cached: false,
    };
  } catch (error) {
    return unavailable(
      "AbuseIPDB",
      error instanceof Error ? error.message : "lookup failed",
      Date.now() - started,
    );
  }
}

/**
 * AlienVault OTX — how many community threat "pulses" reference this address?
 * Requires a free API key; skipped cleanly when unset.
 */
export async function otx(ip: string): Promise<ProviderResult> {
  const started = Date.now();
  const key = process.env.OTX_API_KEY;
  if (!key) {
    return unavailable("AlienVault OTX", "No OTX_API_KEY configured.", 0);
  }
  try {
    const { status, body } = await getJson(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`,
      { headers: { "X-OTX-API-KEY": key } },
    );
    const ms = Date.now() - started;
    if (status !== 200) {
      return unavailable("AlienVault OTX", `OTX returned HTTP ${status}.`, ms);
    }
    const pulseInfo = asRecord(asRecord(body)["pulse_info"]);
    const count = typeof pulseInfo["count"] === "number" ? pulseInfo["count"] : 0;

    return {
      provider: "AlienVault OTX",
      origin: count > 0 ? "live" : "live-clean",
      threat: Math.min(1, count / 12),
      labels: count > 0 ? ["otx-pulse"] : [],
      evidence:
        count > 0
          ? `${ip} appears in ${count} OTX threat pulse${count === 1 ? "" : "es"}.`
          : `${ip} appears in no OTX threat pulses.`,
      reference: `https://otx.alienvault.com/indicator/ip/${ip}`,
      ms,
      cached: false,
    };
  } catch (error) {
    return unavailable(
      "AlienVault OTX",
      error instanceof Error ? error.message : "lookup failed",
      Date.now() - started,
    );
  }
}

/** Every provider, keyless ones first so the common path needs no configuration. */
export const PROVIDERS: readonly ((ip: string) => Promise<ProviderResult>)[] = [
  greynoise,
  shodan,
  abuseipdb,
  otx,
];
