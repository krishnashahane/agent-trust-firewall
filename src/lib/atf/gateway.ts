/**
 * The gateway instance.
 *
 * One store, one keypair, one live risk config, shared by every route in the
 * process. The gateway's X25519 secret key is generated at boot unless pinned
 * via ATF_GATEWAY_SECRET_KEY — it never appears in a response, and there is no
 * code path that serialises it to a client.
 */
import { generateEncryptionKeyPair, encryptionPublicKeyFor } from "./crypto/e2ee.ts";
import { MemoryStore } from "./store/memory.ts";
import { DEFAULT_RISK_CONFIG, type RiskConfig } from "./risk/config.ts";
import { seedDemoWorld } from "./demo/seed.ts";
import type { DemoIdentity } from "./demo/fleet.ts";
import type { Store } from "./store/port.ts";

export interface Gateway {
  store: Store;
  /** X25519 secret — server-side only, never leaves this module */
  secretKey: string;
  publicKey: string;
  bootedAt: number;
  config: RiskConfig;
  /**
   * Demo identities, so the built-in attack range can act as them. Held on the
   * gateway rather than in a module-level global: two gateways (a test and the
   * app, say) must never end up sharing one set of keys.
   */
  identities: Map<string, DemoIdentity>;
}

declare global {
  var __atfGateway: Gateway | undefined;
  var __atfGatewayInit: Promise<Gateway> | undefined;
}

function createGateway(): Gateway {
  const pinned = process.env.ATF_GATEWAY_SECRET_KEY;
  const keys =
    pinned && /^[0-9a-f]{64}$/i.test(pinned)
      ? { secretKey: pinned.toLowerCase(), publicKey: encryptionPublicKeyFor(pinned) }
      : generateEncryptionKeyPair();

  return {
    store: new MemoryStore(),
    secretKey: keys.secretKey,
    publicKey: keys.publicKey,
    bootedAt: Date.now(),
    config: DEFAULT_RISK_CONFIG,
    identities: new Map(),
  };
}

/**
 * Dev servers re-evaluate modules on every edit; without the global the store
 * would silently reset under the running dashboard.
 */
export async function getGateway(): Promise<Gateway> {
  if (globalThis.__atfGateway) return globalThis.__atfGateway;

  // Concurrent first requests must not each seed their own world.
  globalThis.__atfGatewayInit ??= (async () => {
    const gateway = createGateway();
    await seedDemoWorld(gateway);
    globalThis.__atfGateway = gateway;
    return gateway;
  })().catch((error: unknown) => {
    // Critical: clear the memo on failure. A rejected promise left in place
    // would be handed to every later request, turning one transient seeding
    // error into a permanently broken instance.
    globalThis.__atfGatewayInit = undefined;
    throw error;
  });

  return globalThis.__atfGatewayInit;
}

/**
 * Guarantee the instance has traffic to show.
 *
 * Each serverless instance holds its own in-memory world, so a request can land
 * on one that has been reclaimed and re-created. Without this, the console could
 * render an empty feed while the audit page — served moments earlier by another
 * instance — showed a full log, which reads as a bug even though each instance
 * is internally consistent. Re-seeding costs a couple of seconds once per cold
 * instance and keeps every page telling the same story.
 */
export async function getSeededGateway(): Promise<Gateway> {
  const gateway = await getGateway();
  const events = await gateway.store.listEvents(1);
  if (events.length === 0) {
    await seedDemoWorld(gateway);
  }
  return gateway;
}

/** Public half only. Agents seal envelopes to this. */
export async function gatewayPublicKey(): Promise<string> {
  return (await getGateway()).publicKey;
}
