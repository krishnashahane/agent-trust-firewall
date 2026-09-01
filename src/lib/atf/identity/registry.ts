/**
 * Agent enrolment.
 *
 * Enrolment records public keys and a commitment to the agent's capability set.
 * No secret is ever submitted: an agent proves possession of its signing key
 * with a zero-knowledge proof, and the firewall only ever holds the public half.
 */
import { z } from "zod";
import { capabilityRoot, normalizeCapabilities } from "./merkle.ts";
import type { Store } from "../store/port.ts";
import type { AgentRecord } from "../types.ts";

const hex = (bytes: number) =>
  z
    .string()
    .length(bytes * 2, `expected ${bytes} bytes of hex`)
    .regex(/^[0-9a-f]+$/i, "expected hex");

export const registrationSchema = z.object({
  agentId: z
    .string()
    .min(3)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._-]*$/i, "agent ids are alphanumeric with . _ -"),
  displayName: z.string().min(1).max(80),
  signingPublicKey: hex(32),
  encryptionPublicKey: hex(32),
  capabilities: z.array(z.string().min(1).max(64)).min(1).max(64),
  /** optional public IPv4 the agent calls from, for external enrichment */
  originIp: z
    .string()
    .regex(/^\d{1,3}(\.\d{1,3}){3}$/, "expected an IPv4 address")
    .optional(),
});

export type Registration = z.infer<typeof registrationSchema>;

export class DuplicateAgentError extends Error {}

export async function registerAgent(
  store: Store,
  input: Registration,
  now = Date.now(),
): Promise<AgentRecord> {
  const existing = await store.getAgent(input.agentId);
  if (existing) {
    // Re-enrolling over a live id would let anyone displace an agent's key.
    throw new DuplicateAgentError("agent id already enrolled");
  }
  const capabilities = normalizeCapabilities(input.capabilities);
  const agent: AgentRecord = {
    agentId: input.agentId,
    displayName: input.displayName,
    signingPublicKey: input.signingPublicKey.toLowerCase(),
    encryptionPublicKey: input.encryptionPublicKey.toLowerCase(),
    capabilityRoot: capabilityRoot(capabilities),
    declaredCapabilities: capabilities,
    registeredAt: now,
    keyRotatedAt: now,
    ...(input.originIp ? { originIp: input.originIp } : {}),
    revoked: false,
  };
  await store.putAgent(agent);
  return agent;
}

export async function revokeAgent(
  store: Store,
  agentId: string,
  reason: string,
): Promise<AgentRecord | null> {
  const agent = await store.getAgent(agentId);
  if (!agent) return null;
  const revoked: AgentRecord = { ...agent, revoked: true, revocationReason: reason };
  await store.putAgent(revoked);
  return revoked;
}

export async function rotateKey(
  store: Store,
  agentId: string,
  signingPublicKey: string,
  now = Date.now(),
): Promise<AgentRecord | null> {
  const agent = await store.getAgent(agentId);
  if (!agent) return null;
  const rotated: AgentRecord = {
    ...agent,
    signingPublicKey: signingPublicKey.toLowerCase(),
    keyRotatedAt: now,
  };
  await store.putAgent(rotated);
  return rotated;
}
