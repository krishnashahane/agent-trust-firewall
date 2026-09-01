import { describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  hashRecord,
  linkRecord,
  verifyChain,
  type AuditRecord,
} from "@/lib/atf/audit/chain";

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
