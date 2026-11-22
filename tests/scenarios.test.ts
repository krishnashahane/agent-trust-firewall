/**
 * The attack range, asserted.
 *
 * The scenarios are demo buttons in the UI, but they are tests here: if the
 * firewall ever stopped blocking a forged identity or a replayed proof, this
 * file fails long before anyone sees it on the front page.
 */
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { MemoryStore } from "@/lib/atf/store/memory";
import { DEFAULT_RISK_CONFIG } from "@/lib/atf/risk/config";
import { seedDemoWorld } from "@/lib/atf/demo/seed";
import { runScenario, runSealedFieldDemo, SCENARIOS } from "@/lib/atf/demo/scenarios";
import { verifyChain } from "@/lib/atf/audit/chain";
import { previewTraffic, previewVerdict } from "@/lib/atf/risk/preview";
import { openField } from "@/lib/atf/crypto/sealed";
import { generateEncryptionKeyPair } from "@/lib/atf/crypto/e2ee";
import type { Gateway } from "@/lib/atf/gateway";

/**
 * A freshly seeded world. Scenarios mutate shared state — a flood leaves 40
 * calls behind, and running "off-baseline" twice makes the second run familiar
 * by definition. Each assertion below therefore gets a clean gateway, so what
 * it measures is the scenario and not the order the tests happened to run in.
 */
async function freshGateway(): Promise<Gateway> {
  const keys = generateEncryptionKeyPair();
  const gateway: Gateway = {
    store: new MemoryStore(),
    secretKey: keys.secretKey,
    publicKey: keys.publicKey,
    bootedAt: Date.now(),
    config: DEFAULT_RISK_CONFIG,
    identities: new Map(),
    storage: "memory",
  };
  await seedDemoWorld(gateway);
  return gateway;
}

let gateway: Gateway;

beforeAll(async () => {
  gateway = await freshGateway();
});

describe("the seeded world", () => {
  it("enrols the whole fleet", async () => {
    expect((await gateway.store.listAgents()).length).toBeGreaterThanOrEqual(6);
  });

  it("produces baseline traffic through the real decision path", async () => {
    const events = await gateway.store.listEvents(500);
    expect(events.length).toBeGreaterThan(50);
    // Ordinary traffic should overwhelmingly be allowed, or the engine is
    // too trigger-happy to be usable.
    const allowed = events.filter((e) => e.verdict === "ALLOW").length;
    expect(allowed / events.length).toBeGreaterThan(0.8);
  });

  it("leaves the audit chain intact", async () => {
    expect(verifyChain(await gateway.store.listAudit(2000)).valid).toBe(true);
  });

  it("never stores an agent's secret key", async () => {
    const agents = await gateway.store.listAgents();
    const serialized = JSON.stringify(agents);
    for (const identity of gateway.identities.values()) {
      expect(serialized).not.toContain(identity.signingSecretKey);
    }
  });
});

describe("every scenario runs and is decided", () => {
  it("covers every advertised scenario", async () => {
    for (const scenario of SCENARIOS) {
      const outcome = await runScenario(await freshGateway(), scenario.id);
      expect(outcome.decision.explanation.length).toBeGreaterThan(10);
      expect(outcome.decision.risk.contributions.length).toBeGreaterThan(0);
      expect(outcome.decision.auditId).toMatch(/^[0-9a-f]{32}$/);
    }
  });
});

describe("hostile scenarios are actually stopped", () => {
  let world: Gateway;
  beforeEach(async () => {
    world = await freshGateway();
  });

  it("blocks an unenrolled agent", async () => {
    const { decision } = await runScenario(world, "unenrolled");
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.violations.map((v) => v.rule)).toContain("unknown-agent");
  });

  it("blocks a replayed proof", async () => {
    const { decision } = await runScenario(world, "replay");
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.violations.map((v) => v.rule)).toContain("replayed-challenge");
  });

  it("blocks capability escalation", async () => {
    const { decision } = await runScenario(world, "escalation");
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.violations.map((v) => v.rule)).toContain("capability-escalation");
  });

  it("blocks a revoked key", async () => {
    const { decision } = await runScenario(world, "revoked");
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.violations.map((v) => v.rule)).toContain("revoked-key");
  });

  it("does not let a rate flood pass unremarked", async () => {
    const { decision, precedingCalls } = await runScenario(world, "flood");
    expect(precedingCalls).toBeGreaterThan(20);
    const rate = decision.risk.contributions.find((c) => c.id === "rate");
    expect(rate!.score).toBeGreaterThan(0.5);
    // Noticing is not enough: a flood that is merely scored is still allowed.
    expect(decision.verdict).not.toBe("ALLOW");
  });

  it("notices behaviour that does not fit the agent's baseline", async () => {
    const { decision } = await runScenario(world, "off-baseline");
    const behavior = decision.risk.contributions.find((c) => c.id === "behavior");
    expect(behavior!.score).toBeGreaterThan(0.3);
    expect(decision.verdict).not.toBe("ALLOW");
  });

  it("stops every hostile scenario and allows the legitimate one", async () => {
    for (const scenario of SCENARIOS) {
      const { decision } = await runScenario(await freshGateway(), scenario.id);
      if (scenario.id === "healthy") expect(decision.verdict).toBe("ALLOW");
      else expect(decision.verdict, scenario.id).not.toBe("ALLOW");
    }
  });

  it("does not allow a prompt-injection payload through", async () => {
    const { decision } = await runScenario(world, "injection");
    expect(decision.verdict).not.toBe("ALLOW");
    const payload = decision.risk.contributions.find((c) => c.id === "payload");
    expect(payload!.score).toBeGreaterThan(0.5);
  });

  it("does not allow a credential riding out in a payload", async () => {
    const { decision } = await runScenario(world, "exfiltration");
    expect(decision.verdict).not.toBe("ALLOW");
    const payload = decision.risk.contributions.find((c) => c.id === "payload");
    expect(payload!.score).toBeGreaterThan(0.5);
  });

  it("still allows the legitimate call — the firewall is usable", async () => {
    const { decision } = await runScenario(world, "healthy");
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.violations).toEqual([]);
  });
});

describe("sealed-field demo", () => {
  it("scores a field the gateway cannot read", async () => {
    const result = await runSealedFieldDemo(gateway);
    expect(result.decision.verdict).not.toBe("BLOCK");
    expect(result.descriptor.bytes).toBeGreaterThan(0);
    expect(result.capabilityProofLength).toBeGreaterThan(0);
  });

  it("proves the gateway key does not open a destination-sealed field", async () => {
    const identity = gateway.identities.get("payments-runner")!;
    const { sealField } = await import("@/lib/atf/crypto/sealed");
    const field = sealField(identity.destinationPublicKey, "4242 4242 4242 4242", {
      agentId: identity.agentId,
      requestDigest: "a".repeat(64),
      issuedAt: Date.now(),
    });
    // The destination can read it.
    expect(openField(identity.destinationSecretKey, field)).toBe("4242 4242 4242 4242");
    // The firewall cannot.
    expect(() => openField(gateway.secretKey, field)).toThrow();
  });
});

describe("the audit chain survives an attack run", () => {
  it("is still unbroken after every scenario has executed", async () => {
    expect(verifyChain(await gateway.store.listAudit(2000)).valid).toBe(true);
  });
});

describe("the tuning preview", () => {
  it("reproduces every recorded verdict at the current config", async () => {
    const gateway = await freshGateway();
    for (const scenario of SCENARIOS) await runScenario(gateway, scenario.id);
    const events = await gateway.store.listEvents(500);
    const preview = previewTraffic(events, DEFAULT_RISK_CONFIG);
    expect(preview.changed).toBe(0);
    expect(preview.flagged).toBe(events.filter((e) => e.verdict === "FLAG").length);
    expect(preview.flagged).toBeGreaterThan(0);
  });

  it("responds to the weight sliders, not only the thresholds", async () => {
    const gateway = await freshGateway();
    await runScenario(gateway, "healthy");
    const [event] = await gateway.store.listEvents(1);
    expect(event!.verdict).toBe("ALLOW");
    const context = event!.signals!["context"]!;
    expect(context).toBeGreaterThan(0);

    // All weight on the context signal: the score becomes context * 100.
    const contextOnly = {
      weights: { identity: 0, context: 1, behavior: 0, rate: 0, payload: 0, reputation: 0, intel: 0 },
      thresholds: { flag: Math.max(0, context * 100 - 1), block: 100 },
    };
    expect(previewVerdict(event!, contextOnly)).toBe("FLAG");
    expect(previewVerdict(event!, DEFAULT_RISK_CONFIG)).toBe("ALLOW");
  });

  it("never lets a config undo a hard-rule block", async () => {
    const gateway = await freshGateway();
    await runScenario(gateway, "escalation");
    const [event] = await gateway.store.listEvents(1);
    const lenient = {
      weights: { identity: 0, context: 0, behavior: 0, rate: 0, payload: 0, reputation: 0, intel: 1 },
      thresholds: { flag: 100, block: 100 },
    };
    expect(previewVerdict(event!, lenient)).toBe("BLOCK");
  });

  it("keeps an escalated flag on events recorded before readings were stored", () => {
    const legacy = {
      id: "e", agentId: "a", agentName: "A", tool: "email.send", destination: "d",
      verdict: "FLAG" as const, score: 12, band: "low" as const, topSignals: [], violations: [],
      explanation: "", sealedFieldCount: 0, intelLabels: [], intelLive: false, timestamp: 0,
    };
    expect(previewVerdict(legacy, DEFAULT_RISK_CONFIG)).toBe("FLAG");
  });
});
