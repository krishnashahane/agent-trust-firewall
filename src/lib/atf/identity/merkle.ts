/**
 * Selective disclosure of capability grants.
 *
 * An agent's full grant set is committed to as a Merkle root at enrolment. To
 * make a call the agent reveals ONE capability plus an inclusion proof. The
 * firewall learns that this capability was granted, and learns nothing about the
 * rest of the agent's authority — the minimum disclosure the check requires.
 *
 * Leaves and internal nodes use different domain tags, which is what stops the
 * classic second-preimage attack of passing an internal node off as a leaf.
 */
import { bytesToHex, hexToBytes, tagged, utf8 } from "../crypto/primitives.ts";

export interface MerkleProof {
  /** the disclosed capability, e.g. "payments:refund" */
  capability: string;
  /** index of the leaf in the sorted leaf list */
  index: number;
  /** sibling hashes from leaf to root, hex-encoded */
  path: string[];
}

const leafHash = (capability: string): Uint8Array =>
  tagged("atf/merkle-leaf/v1", utf8(capability));

const nodeHash = (l: Uint8Array, r: Uint8Array): Uint8Array =>
  tagged("atf/merkle-node/v1", l, r);

/** Capabilities are de-duplicated and sorted so the root is canonical. */
export const normalizeCapabilities = (caps: readonly string[]): string[] =>
  [...new Set(caps.map((c) => c.trim()).filter(Boolean))].sort();

function levels(caps: string[]): Uint8Array[][] {
  if (caps.length === 0) return [[tagged("atf/merkle-empty/v1")]];
  let level = caps.map(leafHash);
  const all: Uint8Array[][] = [level];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i] as Uint8Array;
      // odd node is promoted by pairing with itself
      const r = (level[i + 1] ?? l) as Uint8Array;
      next.push(nodeHash(l, r));
    }
    level = next;
    all.push(level);
  }
  return all;
}

export function capabilityRoot(capabilities: readonly string[]): string {
  const tree = levels(normalizeCapabilities(capabilities));
  return bytesToHex((tree[tree.length - 1] as Uint8Array[])[0] as Uint8Array);
}

export function proveCapability(
  capabilities: readonly string[],
  capability: string,
): MerkleProof | null {
  const caps = normalizeCapabilities(capabilities);
  const index = caps.indexOf(capability);
  if (index < 0) return null;

  const tree = levels(caps);
  const path: string[] = [];
  let idx = index;
  for (let d = 0; d < tree.length - 1; d++) {
    const level = tree[d] as Uint8Array[];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    const sibling = (level[siblingIdx] ?? level[idx]) as Uint8Array;
    path.push(bytesToHex(sibling));
    idx = Math.floor(idx / 2);
  }
  return { capability, index, path };
}

export function verifyCapability(root: string, proof: MerkleProof): boolean {
  try {
    if (!Number.isInteger(proof.index) || proof.index < 0) return false;
    if (proof.path.length > 32) return false; // bound the work a caller can force
    let hash = leafHash(proof.capability);
    let idx = proof.index;
    for (const siblingHex of proof.path) {
      const sibling = hexToBytes(siblingHex);
      if (sibling.length !== 32) return false;
      hash = idx % 2 === 0 ? nodeHash(hash, sibling) : nodeHash(sibling, hash);
      idx = Math.floor(idx / 2);
    }
    return bytesToHex(hash) === root;
  } catch {
    return false;
  }
}
