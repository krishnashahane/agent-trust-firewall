import { describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  checkConsistency,
  hashRecord,
  linkRecord,
  verifyChain,
  type AuditRecord,
} from "@/lib/atf/audit/chain";
import { signCheckpoint, verifyCheckpointSignature } from "@/lib/atf/audit/checkpoint";
import { MemoryStore } from "@/lib/atf/store/memory";

function chain(count: number): AuditRecord[] {
  const records: AuditRecord[] = [];
  let previous: AuditRecord | null = null;
  for (let i = 0; i < count; i++) {
    const record = linkRecord(
      {
        timestamp: 1_800_000_000_000 + i * 1000,
        agentId: `agent-${i % 3}`,
        tool: "search.query",
        destination: "api.search.internal",
        verdict: i % 4 === 0 ? "BLOCK" : "ALLOW",
        score: i % 4 === 0 ? 88 : 12,
        requestDigest: String(i).padStart(64, "0"),
        violations: [],
      },
      previous,
      `id-${i}`,
    );
    records.push(record);
    previous = record;
  }
  return records;
}

describe("audit chain", () => {
  it("starts from a known genesis", () => {
    expect(chain(1)[0]!.previousHash).toBe(GENESIS_HASH);
    expect(chain(1)[0]!.seq).toBe(0);
  });

  it("verifies an untouched chain", () => {
    const result = verifyChain(chain(50));
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
    expect(result.length).toBe(50);
  });

  it("verifies an empty chain", () => {
    expect(verifyChain([]).valid).toBe(true);
  });

  it("is deterministic — the same record always hashes the same", () => {
    const records = chain(3);
    expect(hashRecord(records[1]!)).toBe(records[1]!.hash);
  });

  it("detects an altered verdict — the exact cover-up an attacker would attempt", () => {
    const records = chain(20);
    records[10] = { ...records[10]!, verdict: "ALLOW", score: 2 };
    const result = verifyChain(records);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(10);
    expect(result.reason).toContain("altered");
  });

  it("detects an altered timestamp", () => {
    const records = chain(10);
    records[4] = { ...records[4]!, timestamp: 0 };
    expect(verifyChain(records).valid).toBe(false);
  });

  it("detects a deleted record", () => {
    const records = chain(10);
    records.splice(5, 1);
    const result = verifyChain(records);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("sequence gap");
  });

  it("detects a record inserted into the middle", () => {
    const records = chain(10);
    const forged = linkRecord(
      {
        timestamp: 1,
        agentId: "attacker",
        tool: "payments.charge",
        destination: "x",
        verdict: "ALLOW",
        score: 0,
        requestDigest: "f".repeat(64),
        violations: [],
      },
      null,
      "forged",
    );
    records.splice(5, 0, forged);
    expect(verifyChain(records).valid).toBe(false);
  });

  it("detects a re-hashed record that no longer links to its predecessor", () => {
    // A sophisticated attacker recomputes the hash after editing. The link to
    // the previous record is what still gives them away.
    const records = chain(10);
    const edited = { ...records[6]!, verdict: "ALLOW" as const, score: 1 };
    records[6] = { ...edited, hash: hashRecord(edited) };
    const result = verifyChain(records);
    expect(result.valid).toBe(false);
    // The break surfaces at the record after the edit, whose previousHash is stale.
    expect(result.brokenAt).toBe(7);
  });

  it("detects a swapped previousHash", () => {
    const records = chain(10);
    records[3] = { ...records[3]!, previousHash: GENESIS_HASH };
    expect(verifyChain(records).valid).toBe(false);
  });

  it("gives every record a unique hash", () => {
    const hashes = new Set(chain(100).map((r) => r.hash));
    expect(hashes.size).toBe(100);
  });
});

/** Rewrite every record from `from` onwards and recompute every hash, as an
 *  operator with full database access could. */
function rewriteFrom(records: AuditRecord[], from: number): AuditRecord[] {
  const out = records.slice(0, from);
  for (const record of records.slice(from)) {
    const previous = out[out.length - 1] ?? null;
    const { seq: _seq, hash: _hash, previousHash: _prev, id, ...input } = record;
    out.push(linkRecord({ ...input, verdict: "ALLOW", score: 1 }, previous, id));
  }
  return out;
}

describe("verifying a window of a longer log", () => {
  it("verifies the most recent records without demanding they start at genesis", () => {
    const result = verifyChain(chain(50).slice(30), { window: true });
    expect(result.valid).toBe(true);
    expect(result.fromSeq).toBe(30);
  });

  it("still catches an edit inside the window", () => {
    const recent = chain(50).slice(30);
    recent[5] = { ...recent[5]!, score: 99 };
    expect(verifyChain(recent, { window: true }).valid).toBe(false);
  });

  it("does not let a full-chain check skip a deleted first record", () => {
    expect(verifyChain(chain(10).slice(1)).valid).toBe(false);
  });
});

describe("checkpoints", () => {
  const SECRET = "ab".repeat(32);

  it("stays consistent while the log only grows", () => {
    const records = chain(40);
    const checkpoint = records[19]!;
    const result = checkConsistency(records.slice(19), checkpoint);
    expect(result).toEqual({ status: "consistent", checkedThrough: 39 });
  });

  it("catches a full rewrite that recomputed every hash", () => {
    const records = chain(40);
    const saved = { seq: records[25]!.seq, hash: records[25]!.hash };
    const rewritten = rewriteFrom(records, 10);
    expect(verifyChain(rewritten).valid).toBe(true); // the chain alone is fooled
    expect(checkConsistency(rewritten.slice(25), saved).status).toBe("rewritten");
  });

  it("says when the server no longer holds the checkpointed record", () => {
    const records = chain(40);
    const result = checkConsistency(records.slice(30), records[10]!);
    expect(result.status).toBe("unavailable");
  });

  it("treats a log that is now shorter than the checkpoint as tampered", () => {
    const records = chain(40);
    const saved = records[35]!;
    expect(checkConsistency([], saved, 20).status).toBe("rewritten");
    expect(checkConsistency([], saved, null).status).toBe("rewritten");
  });

  it("is signed, and a forged or edited checkpoint fails verification", () => {
    const head = chain(5)[4]!;
    const checkpoint = signCheckpoint(head, SECRET, 1_800_000_000_000);
    expect(verifyCheckpointSignature(checkpoint)).toBe(true);
    expect(verifyCheckpointSignature({ ...checkpoint, seq: checkpoint.seq + 1 })).toBe(false);
    expect(verifyCheckpointSignature({ ...checkpoint, hash: "0".repeat(64) })).toBe(false);
  });

  it("is read back from the store from the checkpoint onwards", async () => {
    const store = new MemoryStore();
    for (const record of chain(12)) await store.appendAudit(record);
    const from = await store.auditFrom(7, 100);
    expect(from.map((r) => r.seq)).toEqual([7, 8, 9, 10, 11]);
  });
});
