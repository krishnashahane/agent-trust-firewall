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
  /** seq of the first record checked; 0 means the whole chain from genesis */
  fromSeq: number;
  /** seq of the first record that failed, if any */
  brokenAt: number | null;
  reason: string | null;
}

/**
 * Verify records supplied in ascending seq order.
 *
 * By default the records must be the whole chain, starting at genesis. Pass
 * `{ window: true }` when they are only the most recent part of a longer log:
 * the window is then verified from its first record's own link onwards, and
 * `fromSeq` says so — links before it are not covered. Covering them is what
 * checkpoints are for; see `checkConsistency`.
 */
export function verifyChain(
  records: readonly AuditRecord[],
  opts: { window?: boolean } = {},
): ChainVerification {
  const fromSeq = opts.window ? (records[0]?.seq ?? 0) : 0;
  let previous: AuditRecord | null = null;
  const fail = (record: AuditRecord, reason: string): ChainVerification => ({
    valid: false,
    length: records.length,
    fromSeq,
    brokenAt: record.seq,
    reason,
  });

  for (const record of records) {
    const expectedSeq = previous ? previous.seq + 1 : fromSeq;
    if (record.seq !== expectedSeq) {
      return fail(record, `sequence gap: expected ${expectedSeq}, found ${record.seq}`);
    }
    if (!previous && record.seq === 0 && record.previousHash !== GENESIS_HASH) {
      return fail(record, "the first record does not start from genesis");
    }
    if (previous && record.previousHash !== previous.hash) {
      return fail(record, "record does not link to its predecessor");
    }
    if (hashRecord(record) !== record.hash) {
      return fail(record, "record contents do not match its hash — it was altered");
    }
    previous = record;
  }
  return { valid: true, length: records.length, fromSeq, brokenAt: null, reason: null };
}

export type Consistency =
  /** the checkpointed record is unchanged and every later link verifies */
  | { status: "consistent"; checkedThrough: number }
  /** the record at the checkpoint's position no longer has that hash */
  | { status: "rewritten"; seq: number; reason: string }
  /** the checkpointed record is intact but a later link is broken */
  | { status: "broken"; seq: number; reason: string }
  /** this server no longer holds that record, so the claim cannot be checked */
  | { status: "unavailable"; reason: string };

/**
 * Is a previously saved checkpoint still part of this log?
 *
 * A hash chain alone cannot stop whoever controls the database: they can
 * rewrite every record and recompute every hash. What they cannot do is make
 * the rewritten chain agree with a checkpoint someone else saved before the
 * rewrite. `records` must start at the checkpoint's seq, ascending.
 */
export function checkConsistency(
  records: readonly AuditRecord[],
  checkpoint: { seq: number; hash: string },
  /** seq of the log's current head, or null when the log is empty */
  headSeq: number | null = records.at(-1)?.seq ?? null,
): Consistency {
  if (headSeq === null || headSeq < checkpoint.seq) {
    return {
      status: "rewritten",
      seq: checkpoint.seq,
      reason: "The log is now shorter than when this fingerprint was saved: records were removed or the log was reset.",
    };
  }
  const first = records[0];
  if (!first || first.seq !== checkpoint.seq) {
    return {
      status: "unavailable",
      reason: "This server no longer holds that record, so the checkpoint cannot be checked here.",
    };
  }
  if (first.hash !== checkpoint.hash) {
    return {
      status: "rewritten",
      seq: first.seq,
      reason: "The record at this position has a different hash than when the checkpoint was saved.",
    };
  }
  const chain = verifyChain(records, { window: true });
  if (!chain.valid) {
    return { status: "broken", seq: chain.brokenAt ?? first.seq, reason: chain.reason ?? "" };
  }
  return { status: "consistent", checkedThrough: (records[records.length - 1] as AuditRecord).seq };
}
