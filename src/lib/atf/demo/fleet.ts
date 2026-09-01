/**
 * The demo fleet.
 *
 * Six agents with real keypairs, generated at boot. They stand in for a small
 * production estate so a visitor has something to look at before any traffic
 * arrives. What is synthetic here is the *actors* — the cryptography, the
 * scoring and the verdicts applied to them are the real engine, not a script.
 */
import { generateKeyPair, publicKeyFor } from "../identity/schnorr.ts";
import {
  generateEncryptionKeyPair,
  encryptionPublicKeyFor,
} from "../crypto/e2ee.ts";
import { bytesToHex, tagged, utf8 } from "../crypto/primitives.ts";

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
   * These are cloud-hosting egress addresses — the kind of infrastructure an
   * agent fleet would genuinely run on. An earlier version used well-known
   * public DNS resolvers (8.8.8.8, 9.9.9.9), which any technical visitor spots
   * instantly as implausible agent egress and which undercut the live-data
   * claim made everywhere else on the site.
   *
   * Reserved documentation ranges (RFC 5737 TEST-NET) were considered and
   * rejected: they are not routable, so every provider returns "no record" for
   * them, and the intel feature would be permanently inert and unverifiable.
   * Real routable addresses are what make the lookups checkable by a reader.
   *
   * The hostile origins used by the attack range live in scenarios.ts.
   */
  originIp: string;
}

export const FLEET: readonly DemoAgentSpec[] = [
  {
    agentId: "booking-concierge",
    originIp: "165.227.34.71",
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
    originIp: "51.15.44.7",
    displayName: "Payments Runner",
    capabilities: ["payments:charge", "payments:refund", "identity:lookup"],
    routine: [
      { tool: "payments.charge", destination: "api.payments.internal", capability: "payments:charge" },
      { tool: "identity.lookup", destination: "api.identity.internal", capability: "identity:lookup" },
    ],
  },
  {
    agentId: "research-scout",
    originIp: "45.63.10.22",
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
    originIp: "116.203.19.44",
    displayName: "Ops Deployer",
    capabilities: ["code:review", "storage:read"],
    routine: [
      { tool: "code.review", destination: "api.vcs.internal", capability: "code:review" },
      { tool: "storage.read", destination: "api.storage.internal", capability: "storage:read" },
    ],
  },
  {
    agentId: "support-triage",
    originIp: "172.105.66.19",
    displayName: "Support Triage",
    capabilities: ["email:send", "search:query", "identity:lookup"],
    routine: [
      { tool: "email.send", destination: "api.mail.internal", capability: "email:send" },
      { tool: "search.query", destination: "api.search.internal", capability: "search:query" },
    ],
  },
  {
    agentId: "inventory-sync",
    originIp: "159.65.20.14",
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

/**
 * Derive this demo agent's keys from a seed instead of minting them randomly.
 *
 * Required once storage is durable. Enrolment records a *public* key, and agent
 * secrets are deliberately never stored — so if each serverless instance minted
 * its own keypair, an instance would sign with a key that did not match the
 * enrolment another instance had already persisted, and every scenario would
 * fail with `identity-unproven`. Deriving from a shared seed makes every
 * instance agree without any secret ever reaching the database.
 *
 * The seed is a server-side environment value. When it is absent (local dev,
 * or a fresh clone) keys are random per process, which is fine because nothing
 * is being persisted across instances in that case either.
 *
 * Worth being precise about what this is not: these are synthetic demo actors,
 * and their keys guard nothing. The firewall's real security properties do not
 * depend on them being secret — they depend on the proofs verifying, which they
 * do either way.
 */
/**
 * A stable signing key for a named demo actor.
 *
 * Exported because the attack range needs the same guarantee the fleet does:
 * with durable storage, an actor's enrolled public key and the key an instance
 * signs with must agree, or the scenario fails for the wrong reason.
 */
export function deriveSigningKey(label: string): {
  secretKey: string;
  publicKey: string;
} {
  const seed = process.env.ATF_DEMO_SEED;
  if (!seed) {
    const generated = generateKeyPair();
    return { secretKey: generated.secretKey, publicKey: generated.publicKey };
  }
  const secretKey = bytesToHex(
    tagged("atf/demo-key/v1/signing", utf8(seed), utf8(label)),
  );
  return { secretKey, publicKey: publicKeyFor(secretKey) };
}

function deriveKeys(spec: DemoAgentSpec, seed: string) {
  const scalar = (purpose: string) =>
    bytesToHex(tagged(`atf/demo-key/v1/${purpose}`, utf8(seed), utf8(spec.agentId)));

  const signingSecretKey = scalar("signing");
  const encryptionSecretKey = scalar("encryption");
  const destinationSecretKey = scalar("destination");

  return {
    signingSecretKey,
    signingPublicKey: publicKeyFor(signingSecretKey),
    encryptionPublicKey: encryptionPublicKeyFor(encryptionSecretKey),
    destinationSecretKey,
    destinationPublicKey: encryptionPublicKeyFor(destinationSecretKey),
  };
}

export function mintIdentity(spec: DemoAgentSpec): DemoIdentity {
  const seed = process.env.ATF_DEMO_SEED;

  if (seed) {
    return { ...spec, ...deriveKeys(spec, seed) };
  }

  // No seed configured: random per process. Correct for a single instance,
  // and the only option that does not put a fixed key in the repository.
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
