/**
 * Hash-chained audit log.
 *
 * Each record commits to the hash of the one before it, so the log is
 * append-only in a way that can be *proved* rather than promised: changing or
 * deleting any past record breaks every hash after it, and `verifyChain`
 * reports exactly where.
 *
 * Records store digests and metadata. Raw argument values are never written
 * here — an audit log that leaks the payloads it audits is a liability.
 */
import { digestOf, tagged, bytesToHex, utf8 } from "../crypto/primitives.ts";
import type { PolicyViolation, Verdict } from "../types.ts";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditRecord {
  /** monotonic position in the chain, starting at 0 */
  seq: number;
  id: string;
  timestamp: number;
  agentId: string;
  tool: string;
  destination: string;
  verdict: Verdict;
  score: number;
  /** digest of the request — proves what was decided on without storing it */
  requestDigest: string;
  violations: PolicyViolation[];
  previousHash: string;
  hash: string;
}

export type AuditInput = Omit<AuditRecord, "seq" | "hash" | "previousHash" | "id">;

export function hashRecord(record: Omit<AuditRecord, "hash">): string {
  return bytesToHex(
    tagged(
      "atf/audit/v1",
      utf8(
        digestOf({
          seq: record.seq,
          id: record.id,
          timestamp: record.timestamp,
          agentId: record.agentId,
          tool: record.tool,
          destination: record.destination,
          verdict: record.verdict,
          score: record.score,
          requestDigest: record.requestDigest,
          violations: record.violations,
          previousHash: record.previousHash,
        }),
      ),
    ),
  );
}

export function linkRecord(
  input: AuditInput,
  previous: AuditRecord | null,
  id: string,
): AuditRecord {
  const seq = previous ? previous.seq + 1 : 0;
  const previousHash = previous ? previous.hash : GENESIS_HASH;
  const unsigned = { ...input, seq, id, previousHash };
  return { ...unsigned, hash: hashRecord(unsigned) };
}

export interface ChainVerification {
  valid: boolean;
  length: number;
  /** seq of the first record that failed, if any */
  brokenAt: number | null;
  reason: string | null;
}

/** Records must be supplied in ascending seq order. */
export function verifyChain(records: readonly AuditRecord[]): ChainVerification {
  let previous: AuditRecord | null = null;
  for (const record of records) {
    const expectedSeq = previous ? previous.seq + 1 : 0;
    if (record.seq !== expectedSeq) {
      return {
        valid: false,
        length: records.length,
        brokenAt: record.seq,
        reason: `sequence gap: expected ${expectedSeq}, found ${record.seq}`,
      };
    }
    const expectedPrev = previous ? previous.hash : GENESIS_HASH;
    if (record.previousHash !== expectedPrev) {
      return {
        valid: false,
        length: records.length,
        brokenAt: record.seq,
        reason: "record does not link to its predecessor",
      };
    }
    if (hashRecord(record) !== record.hash) {
      return {
        valid: false,
        length: records.length,
        brokenAt: record.seq,
        reason: "record contents do not match its hash — it was altered",
      };
    }
    previous = record;
  }
  return { valid: true, length: records.length, brokenAt: null, reason: null };
}
