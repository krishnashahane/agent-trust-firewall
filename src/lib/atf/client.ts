/**
 * Agent-side SDK.
 *
 * This is the code an agent runs to make a call through the firewall. It holds
 * the agent's secret key, requests a challenge, produces the zero-knowledge
 * proof and the capability proof, and seals the whole thing to the gateway.
 *
 * It lives in the same repo as the firewall for convenience, but note what it
 * does NOT do: it never transmits the secret key, and there is no field in the
 * envelope that could carry one. The firewall could not learn an agent's key
 * even if it wanted to.
 */
import { prove, type SchnorrProof } from "./identity/schnorr.ts";
import { proveCapability, type MerkleProof } from "./identity/merkle.ts";
import { seal, type SealedEnvelope } from "./crypto/e2ee.ts";
import { sealField } from "./crypto/sealed.ts";
import { requestDigestFor } from "./interceptor/decide.ts";

export interface AgentCredentials {
  agentId: string;
  /** never leaves the agent */
  signingSecretKey: string;
  capabilities: string[];
}

export interface CallSpec {
  tool: string;
  destination: string;
  capability: string;
  args: Record<string, unknown>;
  nonce: string;
  now?: number;
}

export interface SignedCall {
  agentId: string;
  tool: string;
  destination: string;
  nonce: string;
  proof: SchnorrProof;
  capabilityProof: MerkleProof;
  args: Record<string, unknown>;
}

/**
 * Build a signed call. `overrides` exists so the attack range can construct
 * genuinely malformed calls — a proof bound to a different request, a capability
 * the agent does not hold — and watch the firewall reject them. Real crypto,
 * real rejection; nothing is stubbed.
 */
export function signCall(
  credentials: AgentCredentials,
  spec: CallSpec,
  overrides: {
    /** prove against this digest instead of the real one (replay/forgery demos) */
    digest?: string;
    /** claim a capability the agent may not hold */
    forgedCapabilityProof?: MerkleProof;
    proof?: SchnorrProof;
  } = {},
): SignedCall {
  const capabilityProof =
    overrides.forgedCapabilityProof ??
    proveCapability(credentials.capabilities, spec.capability) ?? {
      capability: spec.capability,
      index: 0,
      path: [],
    };

  const base = {
    agentId: credentials.agentId,
    tool: spec.tool,
    destination: spec.destination,
    capabilityProof,
    args: spec.args,
  };

  const digest = overrides.digest ?? requestDigestFor(base);
  const proof =
    overrides.proof ?? prove(credentials.signingSecretKey, spec.nonce, digest);

  return { ...base, nonce: spec.nonce, proof };
}

/** Seal a signed call to the gateway. The outer envelope hides it in transit. */
export function sealCall(
  gatewayPublicKey: string,
  call: SignedCall,
  now = Date.now(),
): SealedEnvelope {
  return seal(gatewayPublicKey, call, {
    agentId: call.agentId,
    requestDigest: requestDigestFor(call),
    issuedAt: now,
  });
}

/**
 * Mark one argument as sensitive: it is encrypted to the destination, and passes
 * through the firewall as ciphertext ATF cannot open.
 */
export function sensitive(
  destinationPublicKey: string,
  value: string,
  agentId: string,
  now = Date.now(),
) {
  return sealField(destinationPublicKey, value, {
    agentId,
    requestDigest: "field",
    issuedAt: now,
  });
}
