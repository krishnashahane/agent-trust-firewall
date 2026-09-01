import { getGateway } from "@/lib/atf/gateway";
import { hashRecord, verifyChain, type AuditRecord } from "@/lib/atf/audit/chain";
import { fail, limit, ok } from "@/lib/guard";

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
    const records = await gateway.store.listAudit(2000);
    const live = verifyChain(records);

    const url = new URL(request.url);
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
        result: verifyChain(copy),
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
