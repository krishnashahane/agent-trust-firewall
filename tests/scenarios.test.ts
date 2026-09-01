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
  });

  it("notices behaviour that does not fit the agent's baseline", async () => {
    const { decision } = await runScenario(world, "off-baseline");
    const behavior = decision.risk.contributions.find((c) => c.id === "behavior");
    expect(behavior!.score).toBeGreaterThan(0.3);
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
