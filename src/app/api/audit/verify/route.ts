import { getGateway } from "@/lib/atf/gateway";
import { z } from "zod";
import { checkConsistency, hashRecord, verifyChain, type AuditRecord } from "@/lib/atf/audit/chain";
import { fail, HttpError, limit, ok } from "@/lib/guard";

const checkpointQuery = z.object({
  seq: z.coerce.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  hash: z.string().regex(/^[0-9a-f]{64}$/),
});

/** How far past a checkpoint one request will walk the chain. */
const CONSISTENCY_LIMIT = 5000;

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Verify the live chain, and — when asked — demonstrate detection by verifying a
 * *copy* with one record altered. The tamper is applied to the copy only; the
 * real log is never modified, which is rather the point of an append-only log.
 */
export async function GET(request: Request) {
  try {
    limit(request, "audit-verify", 60);
    const gateway = await getGateway();
    const url = new URL(request.url);

    if (url.searchParams.has("seq") || url.searchParams.has("hash")) {
      const parsed = checkpointQuery.safeParse({
        seq: url.searchParams.get("seq"),
        hash: url.searchParams.get("hash")?.toLowerCase(),
      });
      if (!parsed.success) throw new HttpError(400, "Invalid request: seq, hash");
      const from = await gateway.store.auditFrom(parsed.data.seq, CONSISTENCY_LIMIT);
      const head = await gateway.store.auditHead();
      return ok({ checkpoint: checkConsistency(from, parsed.data, head?.seq ?? null) });
    }

    const records = await gateway.store.listAudit(2000);
    const live = verifyChain(records, {
      window: (await gateway.store.auditLength()) > records.length,
    });

    if (url.searchParams.get("demo") !== "tamper") {
      return ok({ live, tampered: null });
    }

    if (records.length < 3) {
      return ok({ live, tampered: null, note: "not enough records to demonstrate" });
    }

    const copy: AuditRecord[] = records.map((r) => ({ ...r }));

    // Prefer a record that was actually blocked: turning a BLOCK into an ALLOW
    // is what an attacker covering their tracks would really do. Falling back to
    // the middle record keeps the demo working on a log with no blocks yet — but
    // then the change is a score edit, and the response says so rather than
    // claiming a verdict flip that did not happen.
    const blockedIndex = copy.findIndex((r) => r.verdict === "BLOCK");
    const target = blockedIndex >= 0 ? blockedIndex : Math.floor(copy.length / 2);
    const original = copy[target] as AuditRecord;
    const forged =
      original.verdict === "BLOCK"
        ? { verdict: "ALLOW" as const, score: 3 }
        : { verdict: original.verdict, score: Math.max(0, original.score) + 40 };

    copy[target] = { ...original, ...forged };

    return ok({
      live,
      tampered: {
        result: verifyChain(copy, { window: records[0]!.seq > 0 }),
        alteredSeq: original.seq,
        changed: original.verdict === "BLOCK" ? "verdict" : "score",
        was: { verdict: original.verdict, score: original.score },
        now: forged,
        expectedHash: original.hash,
        recomputedHash: hashRecord(copy[target] as AuditRecord),
      },
    });
  } catch (error) {
    return fail(error);
  }
}
