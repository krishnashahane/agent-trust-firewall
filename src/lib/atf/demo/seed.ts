/**
 * Seeding a world to look at.
 *
 * The dashboard should not open on an empty table, so at boot we enrol the demo
 * fleet and run a half-hour of ordinary traffic through the *real* decision
 * path: every seeded call issues a genuine challenge, produces a genuine
 * proof of key possession and is scored by the genuine engine at a backdated
 * timestamp. Nothing here writes a verdict directly.
 *
 * The one concession to determinism is the random source: seeding uses a
 * seeded PRNG for its choices of tool and timing, so the demo world looks the
 * same shape on every boot. Cryptographic randomness is untouched.
 */
import { registerAgent, rotateKey } from "../identity/registry.ts";
import { capabilityRoot } from "../identity/merkle.ts";
import { issueChallenge } from "../identity/nonce.ts";
import { decide } from "../interceptor/decide.ts";
import { signCall } from "../client.ts";
import { FLEET, mintIdentity, type DemoIdentity } from "./fleet.ts";
import type { Gateway } from "../gateway.ts";

/** Small deterministic PRNG (mulberry32) — for demo shape only, never for keys. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const BENIGN_ARGS: Record<string, Record<string, unknown>> = {
  "calendar.createEvent": { title: "Design review", attendees: 4, durationMinutes: 30 },
  "search.query": { q: "supplier lead times q3", limit: 20 },
  "email.send": { to: "ops@example.internal", subject: "Weekly digest" },
  "payments.charge": { amountMinor: 4900, currency: "USD", reference: "INV-2291" },
  "identity.lookup": { customerRef: "cus_84h2" },
  "storage.read": { key: "reports/2026-08/summary.json" },
  "storage.write": { key: "sync/inventory.json", bytes: 2048 },
  "weather.lookup": { city: "Pune" },
  "code.review": { repo: "internal/api", pullRequest: 812 },
};

/** How far back the seeded history reaches. */
const HISTORY_MS = 28 * 60_000;
const CALLS_PER_AGENT = 12;

/**
 * Enrol the demo fleet.
 *
 * Separated from traffic seeding because the two have very different costs:
 * this is six idempotent upserts of public keys, which every instance needs so
 * that the keys it signs with match what is stored. Generating the traffic is
 * hundreds of statements and belongs out of the request path entirely.
 */
export async function registerFleet(gateway: Gateway): Promise<void> {
  const rand = prng(0x41544601);
  const now = Date.now();
  const identities = gateway.identities;

  for (const spec of FLEET) {
    const identity = mintIdentity(spec);
    identities.set(spec.agentId, identity);

    // Backdate enrolment so agents do not all read as "registered seconds ago",
    // which would make every one of them look suspicious on the identity signal.
    // Math.round matters: this is an epoch timestamp, and rand() makes it
    // fractional. Nothing in the in-process store minded, but a BIGINT column
    // rejects it outright — a good example of a typed store catching what an
    // untyped one hid.
    const registeredAt = Math.round(now - HISTORY_MS - 6 * 3_600_000 * (1 + rand()));

    // Idempotent, because this runs on every cold start against a store that
    // may already hold the fleet. Note what it does *not* do: re-enrol over an
    // existing id. `registerAgent` refuses that deliberately — silently
    // replacing a live agent's key is exactly the takeover the registry exists
    // to prevent — so an existing agent is either left alone or, if its stored
    // key no longer matches what this instance derives, rotated through the
    // sanctioned path.
    const existing = await gateway.store.getAgent(identity.agentId);

    if (!existing) {
      await registerAgent(
        gateway.store,
        {
          agentId: identity.agentId,
          displayName: identity.displayName,
          signingPublicKey: identity.signingPublicKey,
          encryptionPublicKey: identity.encryptionPublicKey,
          capabilityRoot: capabilityRoot(identity.capabilities),
          originIp: identity.originIp,
        },
        registeredAt,
      );
      continue;
    }

    if (existing.signingPublicKey !== identity.signingPublicKey.toLowerCase()) {
      // Reached when ATF_DEMO_SEED changes, or when a stored fleet predates
      // deterministic derivation. Rotating keeps the enrolled key and the key
      // this instance signs with in agreement; without it every scenario would
      // fail with identity-unproven.
      await rotateKey(gateway.store, identity.agentId, identity.signingPublicKey);
    }
  }
}

/**
 * Generate the baseline traffic.
 *
 * Every call here is a genuine challenge, a genuine proof of key possession and a
 * genuine scoring pass at a backdated timestamp — nothing writes a verdict
 * directly. That authenticity is also why it is expensive: against a remote
 * database it is roughly five hundred statements and tens of seconds, so it
 * runs from `npm run seed`, never inside a request.
 */
export async function seedDemoWorld(gateway: Gateway): Promise<void> {
  await registerFleet(gateway);

  // Durable history outlives the instance; replaying the seed would pile
  // duplicate calls into a log whose whole claim is that it is accurate.
  if ((await gateway.store.listEvents(1)).length > 0) return;

  // A fresh generator, seeded identically to the one registerFleet used, so
  // splitting the two functions did not change the world they produce.
  const rand = prng(0x41544601);
  for (let i = 0; i < FLEET.length; i++) rand(); // skip enrolment's draws
  const now = Date.now();
  const identities = gateway.identities;

  // Interleave the fleet's calls in time so the traffic view reads like a live
  // system rather than one agent at a time.
  const timeline: { identity: DemoIdentity; at: number }[] = [];
  for (const identity of identities.values()) {
    for (let i = 0; i < CALLS_PER_AGENT; i++) {
      timeline.push({
        identity,
        at: now - HISTORY_MS + Math.floor(rand() * HISTORY_MS),
      });
    }
  }
  timeline.sort((a, b) => a.at - b.at);

  for (const { identity, at } of timeline) {
    const routine = identity.routine[Math.floor(rand() * identity.routine.length)];
    if (!routine) continue;
    const { nonce } = await issueChallenge(gateway.store, identity.agentId, at);
    const call = signCall(
      {
        agentId: identity.agentId,
        signingSecretKey: identity.signingSecretKey,
        capabilities: identity.capabilities,
      },
      {
        tool: routine.tool,
        destination: routine.destination,
        capability: routine.capability,
        args: BENIGN_ARGS[routine.tool] ?? {},
        nonce,
      },
    );
    await decide(gateway.store, call, { config: gateway.config, now: at });
  }
}
