/**
 * OSINT layer tests.
 *
 * The network is stubbed here on purpose. What matters is not that GreyNoise
 * answers — it is that this layer behaves correctly when it doesn't: that an
 * outage degrades to "unavailable" rather than to "clean", that one dead
 * provider cannot take out the others, that the cache actually prevents repeat
 * calls, and that a hostile address cannot steer our outbound requests.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isPublicIpv4 } from "@/lib/atf/osint/net";
import { lookupIp, resetOsintCache, toExternalIntel } from "@/lib/atf/osint/index";
import { intelSignal } from "@/lib/atf/risk/signals/intel";
import type { RequestContext } from "@/lib/atf/types";

const realFetch = globalThis.fetch;

function stubFetch(handler: (url: string) => { status: number; body: unknown } | "throw") {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const outcome = handler(url);
    if (outcome === "throw") throw new Error("network down");
    return new Response(JSON.stringify(outcome.body), {
      status: outcome.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

beforeEach(() => {
  resetOsintCache();
  delete process.env.ABUSEIPDB_API_KEY;
  delete process.env.OTX_API_KEY;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

describe("address validation (SSRF defence)", () => {
  it("accepts ordinary public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "185.220.101.1", "203.0.114.7"]) {
      expect(isPublicIpv4(ip)).toBe(true);
    }
  });

  it("rejects every private, loopback and reserved range", () => {
    for (const ip of [
      "10.0.0.1",
      "192.168.1.1",
      "172.16.0.1",
      "172.31.255.255",
      "127.0.0.1",
      "0.0.0.0",
      "169.254.169.254", // cloud metadata — the one that matters most
      "100.64.0.1",
      "224.0.0.1",
      "255.255.255.255",
      "198.18.0.1",
    ]) {
      expect(isPublicIpv4(ip)).toBe(false);
    }
  });

  it("rejects malformed input rather than coercing it", () => {
    for (const value of [
      "8.8.8",
      "8.8.8.8.8",
      "8.8.8.256",
      "010.0.0.1", // octal-looking octet
      "8.8.8.-1",
      "example.com",
      "::1",
      "8.8.8.8 ",
      "",
    ]) {
      expect(isPublicIpv4(value)).toBe(false);
    }
  });

  it("does not attempt a lookup for a non-public address", async () => {
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    const intel = await lookupIp("169.254.169.254");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(intel.live).toBe(false);
    expect(intel.threat).toBe(0);
  });
});

describe("provider aggregation", () => {
  it("reads a hostile address from real provider shapes", async () => {
    stubFetch((url) =>
      url.includes("greynoise")
        ? {
            status: 200,
            body: {
              ip: "185.220.101.1",
              noise: true,
              riot: false,
              classification: "malicious",
              last_seen: "2026-08-31",
            },
          }
        : {
            status: 200,
            body: {
              ip: "185.220.101.1",
              ports: [80, 443, 9001],
              tags: ["tor"],
              vulns: [],
              hostnames: ["berlin01.tor-exit.example.org"],
              cpes: [],
            },
          },
    );

    const intel = await lookupIp("185.220.101.1");
    expect(intel.live).toBe(true);
    expect(intel.threat).toBeGreaterThan(0.6);
    expect(intel.labels).toContain("tor");
    expect(intel.labels).toContain("malicious");
  });

  it("treats a clean answer as clean, not as absent", async () => {
    stubFetch((url) =>
      url.includes("greynoise")
        ? { status: 404, body: { ip: "8.8.8.8", noise: false, riot: false } }
        : { status: 404, body: { detail: "No information available" } },
    );
    const intel = await lookupIp("8.8.8.8");
    expect(intel.live).toBe(true); // we did learn something: nothing is known
    expect(intel.threat).toBe(0);
    // The keyless providers answered; the key-gated ones are correctly absent.
    const keyless = intel.providers.filter((p) =>
      ["GreyNoise", "Shodan InternetDB"].includes(p.provider),
    );
    expect(keyless).toHaveLength(2);
    expect(keyless.every((p) => p.origin === "live-clean")).toBe(true);
  });

  it("degrades to unavailable — never to clean — when every provider is down", async () => {
    stubFetch(() => "throw");
    const intel = await lookupIp("8.8.8.8");
    expect(intel.live).toBe(false);
    expect(intel.threat).toBe(0);
    expect(intel.providers.every((p) => p.origin === "unavailable")).toBe(true);
  });

  it("keeps the surviving provider when one fails", async () => {
    stubFetch((url) =>
      url.includes("greynoise")
        ? "throw"
        : {
            status: 200,
            body: { ip: "1.2.3.4", ports: [22], tags: ["tor"], vulns: [], hostnames: [] },
          },
    );
    const intel = await lookupIp("1.2.3.4");
    expect(intel.live).toBe(true);
    expect(intel.labels).toContain("tor");
    expect(intel.providers.some((p) => p.origin === "unavailable")).toBe(true);
  });

  it("takes the worst provider's view rather than averaging it away", async () => {
    stubFetch((url) =>
      url.includes("greynoise")
        ? { status: 404, body: { noise: false } } // clean
        : {
            status: 200,
            body: { ports: [], tags: ["tor"], vulns: ["CVE-2021-1"], hostnames: [] },
          },
    );
    const intel = await lookupIp("1.2.3.5");
    expect(intel.threat).toBeGreaterThan(0.6);
  });

  it("skips key-gated providers cleanly when unconfigured", async () => {
    stubFetch(() => ({ status: 404, body: { noise: false } }));
    const intel = await lookupIp("1.2.3.6");
    const abuse = intel.providers.find((p) => p.provider === "AbuseIPDB");
    expect(abuse?.origin).toBe("unavailable");
    expect(abuse?.evidence).toContain("ABUSEIPDB_API_KEY");
  });
});

describe("caching", () => {
  it("serves a repeat lookup from cache instead of calling out again", async () => {
    let calls = 0;
    stubFetch(() => {
      calls++;
      return { status: 404, body: { noise: false } };
    });

    await lookupIp("8.8.4.4");
    const first = calls;
    expect(first).toBeGreaterThan(0);

    const second = await lookupIp("8.8.4.4");
    expect(calls).toBe(first);
    expect(second.providers.every((p) => p.cached)).toBe(true);
  });

  it("collapses concurrent lookups of the same address into one call", async () => {
    let calls = 0;
    stubFetch(() => {
      calls++;
      return { status: 404, body: { noise: false } };
    });

    await Promise.all(Array.from({ length: 10 }, () => lookupIp("9.9.9.9")));
    // Two keyless providers, one round each — not ten.
    expect(calls).toBeLessThanOrEqual(2);
  });

  it("caches a failed lookup only briefly", async () => {
    stubFetch(() => "throw");
    const intel = await lookupIp("9.9.9.10");
    expect(intel.expiresAt - intel.fetchedAt).toBeLessThanOrEqual(2 * 60_000);
  });
});

describe("the intel risk signal", () => {
  const base: RequestContext = {
    agentId: "a",
    agent: null,
    tool: "search.query",
    destination: "api.search.internal",
    claimedCapability: "search:query",
    capabilityProven: true,
    identityProven: true,
    nonceFresh: true,
    requestDigest: "d".repeat(64),
    argumentSummary: {
      fieldCount: 1,
      totalBytes: 10,
      sealedFieldCount: 0,
      maxEntropy: 2,
      descriptorMismatch: false,
    },
    inspectableText: "",
    timestamp: Date.now(),
    history: [],
  };

  it("contributes nothing when no intel was fetched", () => {
    expect(intelSignal(base).score).toBe(0);
  });

  it("contributes nothing — and says why — when providers were unavailable", () => {
    const signal = intelSignal({
      ...base,
      originIp: "1.2.3.4",
      externalIntel: {
        ip: "1.2.3.4",
        threat: 0,
        labels: [],
        summary: "n/a",
        live: false,
      },
    });
    expect(signal.score).toBe(0);
    expect(signal.evidence).toContain("unavailable");
  });

  it("scores a live hostile finding", () => {
    const signal = intelSignal({
      ...base,
      originIp: "185.220.101.1",
      externalIntel: {
        ip: "185.220.101.1",
        threat: 0.9,
        labels: ["tor", "malicious"],
        summary: "GreyNoise classifies it as malicious.",
        live: true,
      },
    });
    expect(signal.score).toBeCloseTo(0.9);
    expect(signal.evidence).toContain("malicious");
  });

  it("cannot exceed 1 even if a provider over-reports", () => {
    const signal = intelSignal({
      ...base,
      externalIntel: {
        ip: "1.2.3.4",
        threat: 4,
        labels: [],
        summary: "x",
        live: true,
      },
    });
    expect(signal.score).toBe(1);
  });
});

describe("external intel summary", () => {
  it("names the providers that found something", async () => {
    stubFetch((url) =>
      url.includes("greynoise")
        ? { status: 200, body: { noise: true, classification: "malicious" } }
        : { status: 404, body: { detail: "No information available" } },
    );
    const summary = toExternalIntel(await lookupIp("185.220.101.2"));
    expect(summary.live).toBe(true);
    expect(summary.summary).toContain("GreyNoise");
  });

  it("is explicit when nothing was reachable", async () => {
    stubFetch(() => "throw");
    const summary = toExternalIntel(await lookupIp("185.220.101.3"));
    expect(summary.live).toBe(false);
    expect(summary.summary).toContain("No external threat intelligence");
  });
});
