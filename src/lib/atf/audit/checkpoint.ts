/**
 * Signed audit checkpoints.
 *
 * A checkpoint is the chain's head — its position and hash — signed by the
 * gateway with an ordinary Ed25519 key. Anyone can save one and check it later
 * with `checkConsistency`. Two properties follow:
 *
 *  - If the log is later rewritten, the saved checkpoint stops matching, even
 *    if every hash in the rewritten chain was recomputed.
 *  - The signature shows this server issued that head, so an operator cannot
 *    deny an old checkpoint after rewriting history.
 *
 * The signing key is derived from the gateway secret, so it is stable whenever
 * ATF_GATEWAY_SECRET_KEY is pinned.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, canonicalize, hexToBytes, tagged, utf8 } from "../crypto/primitives.ts";
import type { AuditRecord } from "./chain.ts";

export interface Checkpoint {
  v: 1;
  /** position of the head record */
  seq: number;
  /** hash of the head record */
  hash: string;
  issuedAt: number;
  /** Ed25519 public key that signed it, hex */
  publicKey: string;
  /** Ed25519 signature over the canonical checkpoint body, hex */
  signature: string;
}

const signingSeed = (gatewaySecretKey: string): Uint8Array =>
  tagged("atf/checkpoint-key/v1", hexToBytes(gatewaySecretKey));

export const checkpointPublicKey = (gatewaySecretKey: string): string =>
  bytesToHex(ed25519.getPublicKey(signingSeed(gatewaySecretKey)));

const message = (body: { v: 1; seq: number; hash: string; issuedAt: number }): Uint8Array =>
  utf8(`atf-checkpoint:${canonicalize(body)}`);

export function signCheckpoint(
  head: Pick<AuditRecord, "seq" | "hash">,
  gatewaySecretKey: string,
  now = Date.now(),
): Checkpoint {
  const body = { v: 1 as const, seq: head.seq, hash: head.hash, issuedAt: now };
  const seed = signingSeed(gatewaySecretKey);
  return {
    ...body,
    publicKey: bytesToHex(ed25519.getPublicKey(seed)),
    signature: bytesToHex(ed25519.sign(message(body), seed)),
  };
}

/** True when the signature is valid for the key the checkpoint names. */
export function verifyCheckpointSignature(checkpoint: Checkpoint): boolean {
  try {
    const { v, seq, hash, issuedAt } = checkpoint;
    return ed25519.verify(
      hexToBytes(checkpoint.signature),
      message({ v, seq, hash, issuedAt }),
      hexToBytes(checkpoint.publicKey),
    );
  } catch {
    return false;
  }
}
