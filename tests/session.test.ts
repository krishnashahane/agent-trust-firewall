/**
 * Configuration sandboxing.
 *
 * The property under test is the one that was originally broken: a visitor
 * changing the risk configuration must not change what any other visitor sees,
 * and must not be able to weaken the hard rules for anybody — including
 * themselves.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  clearSessionConfig,
  configFor,
  hasSandbox,
  isValidSessionId,
  newSessionId,
  resetSessions,
  sessionCount,
  setSessionConfig,
} from "@/lib/atf/session";
import { DEFAULT_RISK_CONFIG, type RiskConfig } from "@/lib/atf/risk/config";
import { MemoryStore } from "@/lib/atf/store/memory";
import { registerAgent, revokeAgent } from "@/lib/atf/identity/registry";
import { capabilityRoot } from "@/lib/atf/identity/merkle";
import { issueChallenge } from "@/lib/atf/identity/nonce";
import { decide } from "@/lib/atf/interceptor/decide";
import { signCall } from "@/lib/atf/client";
import { generateKeyPair } from "@/lib/atf/identity/schnorr";
import { generateEncryptionKeyPair } from "@/lib/atf/crypto/e2ee";

const permissive: RiskConfig = {
  weights: {
    identity: 0,
    context: 0,
    behavior: 0,
    rate: 0,
    payload: 0,
    reputation: 0,
    intel: 0,
  },
  thresholds: { flag: 100, block: 100 },
};

beforeEach(() => resetSessions());

describe("session ids", () => {
  it("mints opaque 128-bit hex ids", () => {
    const id = newSessionId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(isValidSessionId(id)).toBe(true);
  });

  it("rejects anything that is not a well-formed id", () => {
    for (const value of ["", "abc", "../../etc/passwd", "Z".repeat(32), undefined]) {
      expect(isValidSessionId(value as string | undefined)).toBe(false);
    }
  });

  it("mints unpredictable ids", () => {
    const seen = new Set(Array.from({ length: 500 }, () => newSessionId()));
    expect(seen.size).toBe(500);
  });
});

describe("isolation between visitors", () => {
  it("one visitor's config never reaches another", () => {
    const a = newSessionId();
    const b = newSessionId();
    setSessionConfig(a, permissive);

    expect(configFor(a).thresholds.block).toBe(100);
    // B never applied anything and must still see the shared defaults.
    expect(configFor(b)).toEqual(DEFAULT_RISK_CONFIG);
    expect(hasSandbox(b)).toBe(false);
  });

  it("an unknown or absent session falls back to the shared defaults", () => {
    expect(configFor(undefined)).toEqual(DEFAULT_RISK_CONFIG);
    expect(configFor("not-a-session")).toEqual(DEFAULT_RISK_CONFIG);
    expect(configFor(newSessionId())).toEqual(DEFAULT_RISK_CONFIG);
  });

  it("expires a sandbox rather than holding it forever", () => {
    const id = newSessionId();
    const now = Date.now();
    setSessionConfig(id, permissive, now);
    expect(configFor(id, now + 60_000).thresholds.block).toBe(100);
    // Past the TTL the visitor is back on the shared defaults.
    expect(configFor(id, now + 2 * 60 * 60_000)).toEqual(DEFAULT_RISK_CONFIG);
  });

  it("can be cleared back to defaults on request", () => {
    const id = newSessionId();
    setSessionConfig(id, permissive);
    clearSessionConfig(id);
    expect(configFor(id)).toEqual(DEFAULT_RISK_CONFIG);
  });

  it("is bounded so sandboxes cannot grow memory without limit", () => {
    const now = Date.now();
    for (let i = 0; i < 2500; i++) {
      setSessionConfig(newSessionId(), DEFAULT_RISK_CONFIG, now);
    }
    expect(sessionCount()).toBeLessThanOrEqual(2000);
  });
});

describe("a sandbox cannot disable a hard rule", () => {
  it("blocks a revoked key even under the most permissive sandbox", async () => {
    const store = new MemoryStore();
    const signing = generateKeyPair();
    const encryption = generateEncryptionKeyPair();
    const capabilities = ["search:query"];

    await registerAgent(store, {
      agentId: "agent-1",
      displayName: "Agent One",
      signingPublicKey: signing.publicKey,
      encryptionPublicKey: encryption.publicKey,
      capabilityRoot: capabilityRoot(capabilities),
    });
    await revokeAgent(store, "agent-1", "key leaked");

    const { nonce } = await issueChallenge(store, "agent-1");
    const call = signCall(
      { agentId: "agent-1", signingSecretKey: signing.secretKey, capabilities },
      {
        tool: "search.query",
        destination: "api.search.internal",
        capability: "search:query",
        args: { q: "x" },
        nonce,
      },
    );

    const decision = await decide(store, call, { config: permissive });
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.violations.map((v) => v.rule)).toContain("revoked-key");
  });
});
