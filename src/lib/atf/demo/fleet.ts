/**
 * The demo fleet.
 *
 * Six agents with real keypairs, generated at boot. They stand in for a small
 * production estate so a visitor has something to look at before any traffic
 * arrives. What is synthetic here is the *actors* — the cryptography, the
 * scoring and the verdicts applied to them are the real engine, not a script.
 */
import { generateKeyPair } from "../identity/schnorr.ts";
import { generateEncryptionKeyPair } from "../crypto/e2ee.ts";

export interface DemoAgentSpec {
  agentId: string;
  displayName: string;
  capabilities: string[];
  /** what this agent normally does, used to generate a plausible baseline */
  routine: { tool: string; destination: string; capability: string }[];
  /**
   * A real, public IPv4 address this synthetic agent "calls from".
   *
   * Be precise about what is and is not real here, because the distinction is
   * the whole point: the *agent* is synthetic, but the address is a genuine
   * public address and everything ATF displays about it is fetched live from
   * third-party threat intelligence at request time. Nothing about these
   * addresses is hardcoded — if GreyNoise or Shodan change their assessment,
   * this product's verdicts change with them.
   *
   * The well-known resolvers below are used for the healthy fleet precisely
   * because they are unambiguously benign infrastructure; the hostile origins
   * used by the attack range live in scenarios.ts.
   */
  originIp: string;
}

export const FLEET: readonly DemoAgentSpec[] = [
  {
    agentId: "booking-concierge",
    originIp: "1.1.1.1",
    displayName: "Booking Concierge",
    capabilities: ["calendar:*", "search:query", "email:send"],
    routine: [
      { tool: "calendar.createEvent", destination: "api.calendar.internal", capability: "calendar:*" },
      { tool: "search.query", destination: "api.search.internal", capability: "search:query" },
      { tool: "email.send", destination: "api.mail.internal", capability: "email:send" },
    ],
  },
  {
    agentId: "payments-runner",
    originIp: "8.8.8.8",
    displayName: "Payments Runner",
    capabilities: ["payments:charge", "payments:refund", "identity:lookup"],
    routine: [
      { tool: "payments.charge", destination: "api.payments.internal", capability: "payments:charge" },
      { tool: "identity.lookup", destination: "api.identity.internal", capability: "identity:lookup" },
    ],
  },
  {
    agentId: "research-scout",
    originIp: "9.9.9.9",
    displayName: "Research Scout",
    capabilities: ["search:query", "storage:read", "weather:lookup"],
    routine: [
      { tool: "search.query", destination: "api.search.internal", capability: "search:query" },
      { tool: "storage.read", destination: "api.storage.internal", capability: "storage:read" },
      { tool: "weather.lookup", destination: "api.weather.internal", capability: "weather:lookup" },
    ],
  },
  {
    agentId: "ops-deployer",
    originIp: "8.8.4.4",
    displayName: "Ops Deployer",
    capabilities: ["code:review", "storage:read"],
    routine: [
      { tool: "code.review", destination: "api.vcs.internal", capability: "code:review" },
      { tool: "storage.read", destination: "api.storage.internal", capability: "storage:read" },
    ],
  },
  {
    agentId: "support-triage",
    originIp: "1.0.0.1",
    displayName: "Support Triage",
    capabilities: ["email:send", "search:query", "identity:lookup"],
    routine: [
      { tool: "email.send", destination: "api.mail.internal", capability: "email:send" },
      { tool: "search.query", destination: "api.search.internal", capability: "search:query" },
    ],
  },
  {
    agentId: "inventory-sync",
    originIp: "208.67.222.222",
    displayName: "Inventory Sync",
    capabilities: ["storage:read", "storage:write", "search:query"],
    routine: [
      { tool: "storage.write", destination: "api.storage.internal", capability: "storage:write" },
      { tool: "storage.read", destination: "api.storage.internal", capability: "storage:read" },
    ],
  },
] as const;

export interface DemoIdentity extends DemoAgentSpec {
  signingSecretKey: string;
  signingPublicKey: string;
  encryptionPublicKey: string;
  /** the destination's key, so sealed fields have somewhere real to go */
  destinationSecretKey: string;
  destinationPublicKey: string;
}

export function mintIdentity(spec: DemoAgentSpec): DemoIdentity {
  const signing = generateKeyPair();
  const encryption = generateEncryptionKeyPair();
  const destination = generateEncryptionKeyPair();
  return {
    ...spec,
    signingSecretKey: signing.secretKey,
    signingPublicKey: signing.publicKey,
    encryptionPublicKey: encryption.publicKey,
    destinationSecretKey: destination.secretKey,
    destinationPublicKey: destination.publicKey,
  };
}
