"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Button,
  EmptyState,
  LoadingRegion,
  Panel,
  Skeleton,
  VerdictBadge,
} from "@/components/ui";
import { Counter, useReducedMotion } from "@/components/motion";
import { CopyValue } from "@/components/CopyValue";
import { CheckpointPanel } from "@/components/CheckpointPanel";
import type { Verdict } from "@/lib/atf/types";

interface AuditRecord {
  seq: number;
  id: string;
  timestamp: number;
  agentId: string;
  tool: string;
  destination: string;
  verdict: Verdict;
  score: number;
  requestDigest: string;
  violations: { rule: string; detail: string }[];
  previousHash: string;
  hash: string;
}

interface Verification {
  valid: boolean;
  length: number;
  brokenAt: number | null;
  reason: string | null;
}

interface TamperDemo {
  result: Verification;
  alteredSeq: number;
  changed: "verdict" | "score";
  was: { verdict: Verdict; score: number };
  now: { verdict: Verdict; score: number };
  expectedHash: string;
  recomputedHash: string;
}

const CHAIN_LINKS = 7;

/**
 * The audit log.
 *
 * The forge demo is the most convincing thing on this page and previously got
 * no motion at all: a text result appeared and that was that. Now the tamper is
 * shown as what it actually is — one record's hash stops matching, and every
 * link after it comes apart in sequence. The animation is a faithful rendering
 * of what `verifyChain` reports, not an embellishment of it.
 */
export function AuditView() {
  const reduced = useReducedMotion();
  const [records, setRecords] = useState<AuditRecord[] | null>(null);
  const [length, setLength] = useState(0);
  const [durable, setDurable] = useState<boolean | null>(null);
  const [live, setLive] = useState<Verification | null>(null);
  const [tamper, setTamper] = useState<TamperDemo | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  /** how many links past the break have visibly come apart */
  const [broken, setBroken] = useState(0);

  const load = useCallback(async () => {
    try {
      const [auditResponse, verifyResponse] = await Promise.all([
        fetch("/api/audit", { cache: "no-store" }),
        fetch("/api/audit/verify", { cache: "no-store" }),
      ]);
      if (!auditResponse.ok || !verifyResponse.ok) throw new Error();
      const audit = (await auditResponse.json()) as {
        records: AuditRecord[];
        length: number;
        durable: boolean;
      };
      const verification = (await verifyResponse.json()) as { live: Verification };
      setRecords(audit.records);
      setLength(audit.length);
      setDurable(audit.durable);
      setLive(verification.live);
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    const first = setTimeout(() => void load(), 0);
    return () => clearTimeout(first);
  }, [load]);

  const runTamper = async () => {
    setBusy(true);
    setBroken(0);
    const timers: ReturnType<typeof setTimeout>[] = [];
    try {
      const response = await fetch("/api/audit/verify?demo=tamper", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const data = (await response.json()) as { tampered: TamperDemo | null };
      setTamper(data.tampered);

      if (data.tampered && !reduced) {
        // Walk the break outward from the altered record: the point is that it
        // is not one broken record, it is everything after it.
        for (let i = 1; i <= CHAIN_LINKS; i++) {
          timers.push(setTimeout(() => setBroken(i), 90 * i));
        }
      } else {
        setBroken(CHAIN_LINKS);
      }
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };

  const verifying = live === null && !error;

  return (
    <div className="space-y-4">
      <Panel
        title="Chain integrity"
        caption="Each entry is sealed together with the one before it, like links in a chain. Change or delete any past entry and every link after it breaks."
        action={
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void runTamper()}
            disabled={busy || verifying}
          >
            {busy ? "Forging…" : "Try to forge a record"}
          </Button>
        }
      >
        <div className="px-4 py-4 sm:px-5">
          {verifying ? (
            <LoadingRegion label="Verifying the hash chain">
              <div className="flex flex-wrap items-center gap-3">
                <Skeleton width={172} height={26} style={{ borderRadius: 999 }} />
                <Skeleton width={132} height={11} />
              </div>
            </LoadingRegion>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <span
                className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[12px] font-medium"
                style={{
                  background: live?.valid ? "var(--allow-soft)" : "var(--block-soft)",
                  color: live?.valid ? "var(--allow)" : "var(--block)",
                  borderColor: live?.valid ? "var(--allow-line)" : "var(--block-line)",
                }}
              >
                <span
                  aria-hidden="true"
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ background: live?.valid ? "var(--allow)" : "var(--block)" }}
                />
                {live?.valid ? "Chain verified — unbroken" : "Chain broken"}
              </span>
              <span className="text-[12px] text-[var(--text-muted)]">
                <Counter value={length} /> record{length === 1 ? "" : "s"} in the chain
              </span>
            </div>
          )}

          {live && !live.valid ? (
            <p className="mt-2.5 text-[12.5px] text-[var(--block)]">
              Broken at sequence {live.brokenAt}: {live.reason}
            </p>
          ) : null}

          {tamper ? (
            <div
              className="mt-4 rounded-[var(--r)] border px-4 py-3.5"
              style={{ borderColor: "var(--block-line)", background: "var(--block-soft)" }}
            >
              <h3 className="text-[13px] font-semibold text-[var(--block)]">
                Forgery attempt on a copy of the log — detected
              </h3>

              <p className="mt-1.5 text-[12.5px] leading-relaxed text-[var(--text)]">
                {tamper.changed === "verdict" ? (
                  <>
                    Record {tamper.alteredSeq} was rewritten from{" "}
                    <b>{tamper.was.verdict}</b> to <b>{tamper.now.verdict}</b> — exactly
                    what an attacker covering their tracks would do.
                  </>
                ) : (
                  <>
                    Record {tamper.alteredSeq}&rsquo;s risk score was rewritten from{" "}
                    <b>{tamper.was.score.toFixed(0)}</b> to{" "}
                    <b>{tamper.now.score.toFixed(0)}</b> — falsifying how dangerous a
                    call was judged to be.
                  </>
                )}
              </p>

              <ChainVisual altered={tamper.alteredSeq} broken={broken} />

              <p className="mt-3 text-[12px] font-medium text-[var(--block)]">
                {tamper.result.reason} (at sequence {tamper.result.brokenAt})
              </p>

              <dl className="mono mt-2.5 space-y-1 text-[10.5px] text-[var(--text-muted)]">
                <div className="flex gap-1">
                  <dt className="shrink-0 text-[var(--text-faint)]">stored hash</dt>
                  <dd className="min-w-0">
                    <CopyValue
                      value={tamper.expectedHash}
                      display={`${tamper.expectedHash.slice(0, 34)}…`}
                      title="stored hash"
                    />
                  </dd>
                </div>
                <div className="flex gap-1">
                  <dt className="shrink-0 text-[var(--text-faint)]">recomputed</dt>
                  <dd className="min-w-0">
                    <CopyValue
                      value={tamper.recomputedHash}
                      display={`${tamper.recomputedHash.slice(0, 34)}…`}
                      title="recomputed hash"
                    />
                  </dd>
                </div>
              </dl>

              <p className="mt-2.5 text-[11px] leading-relaxed text-[var(--text-muted)]">
                The real log was never touched — the tamper was applied to a copy, which
                is the only honest way to demonstrate an append-only log.
              </p>
            </div>
          ) : null}
        </div>
      </Panel>

      <CheckpointPanel />

      <Panel
        title="Audit records"
        caption={`Who asked for what, and the verdict. Each request is kept as a fingerprint, never its contents, so the log cannot leak what it records.${
          durable === true
            ? " The chain is persisted, so it survives restarts and redeploys."
            : durable === false
              ? " This instance has no database configured, so the chain lives in memory and starts over when the server restarts."
              : ""
        }`}
      >
        {error ? (
          <EmptyState
            tone="error"
            title="Could not load the audit log"
            body="The audit endpoint did not respond."
            action={
              <Button size="sm" variant="secondary" onClick={() => void load()}>
                Retry
              </Button>
            }
          />
        ) : records === null ? (
          <LoadingRegion label="Reading the chain">
            <div className="scroll-x">
              <table className="w-full min-w-[700px] text-left text-[12px]">
                <thead>
                  <tr className="border-b border-[var(--border)] text-[10.5px] uppercase tracking-[0.06em] text-[var(--text-faint)]">
                    {["Seq", "Verdict", "Agent", "Tool", "Request digest", "Links to"].map(
                      (h) => (
                        <th
                          key={h}
                          className="px-3 py-2 font-medium first:pl-4 sm:first:pl-5"
                        >
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {Array.from({ length: 10 }, (_, i) => (
                    <tr key={i}>
                      <td className="px-3 py-2.5 pl-4 sm:pl-5">
                        <Skeleton width={18} height={9} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Skeleton width={64} height={18} style={{ borderRadius: 999 }} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Skeleton width={96} height={9} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Skeleton width={110} height={9} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Skeleton width={84} height={9} />
                      </td>
                      <td className="px-3 py-2.5">
                        <Skeleton width={84} height={9} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </LoadingRegion>
        ) : records.length === 0 ? (
          <EmptyState
            title="Nothing recorded yet"
            body="Every decision — allowed or blocked — writes one record. Run something in the attack range and it will appear here."
            action={
              <Button size="sm" variant="secondary" href="/console/attack-range">
                Open the attack range
              </Button>
            }
          />
        ) : (
          <div className="scroll-x">
            <table className="sticky-head w-full min-w-[700px] text-left text-[12px]">
              <caption className="sr-only">
                Hash-chained audit records, newest first
              </caption>
              <thead>
                <tr className="border-b border-[var(--border)] text-[10.5px] uppercase tracking-[0.06em] text-[var(--text-faint)]">
                  <th scope="col" className="px-3 py-2 pl-4 font-medium sm:pl-5">
                    Seq
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Verdict
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Agent
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Tool
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Request digest
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Links to
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {records.map((record) => (
                  <tr key={record.id} className="row-hover">
                    <td className="mono tnum px-3 py-2.5 pl-4 text-[var(--text-faint)] sm:pl-5">
                      {record.seq}
                    </td>
                    <td className="px-3 py-2.5">
                      <VerdictBadge verdict={record.verdict} size="sm" />
                    </td>
                    <td className="mono px-3 py-2.5 text-[var(--text-muted)]">
                      {record.agentId}
                    </td>
                    <td className="mono px-3 py-2.5">{record.tool}</td>
                    <td className="px-3 py-2.5 text-[var(--text-faint)]">
                      <CopyValue
                        value={record.requestDigest}
                        display={`${record.requestDigest.slice(0, 14)}…`}
                        title="request digest"
                      />
                    </td>
                    <td className="px-3 py-2.5 text-[var(--text-faint)]">
                      <CopyValue
                        value={record.previousHash}
                        display={`${record.previousHash.slice(0, 14)}…`}
                        title="previous hash"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

/**
 * A miniature of the chain around the altered record.
 *
 * Left of the tamper the links stay intact; from the tamper rightward they come
 * apart one at a time. This is the mental model the hash chain actually
 * implements — the damage propagates forward, it does not stay local.
 */
function ChainVisual({ altered, broken }: { altered: number; broken: number }) {
  return (
    <div
      className="mt-3.5 flex flex-wrap items-center gap-1"
      role="img"
      aria-label={`Record ${altered} was altered; every record after it fails verification.`}
    >
      {Array.from({ length: CHAIN_LINKS }, (_, i) => {
        // Index 2 stands for the altered record; everything right of it breaks.
        const isAltered = i === 2;
        const isAfter = i > 2;
        const gone = isAltered ? broken >= 1 : isAfter ? broken >= i : false;

        return (
          <div key={i} className="flex items-center gap-1">
            <span
              className={gone ? "chain-break" : ""}
              style={{
                display: "block",
                width: 26,
                height: 16,
                borderRadius: 4,
                border: `1.5px solid ${
                  gone ? "var(--block)" : isAltered ? "var(--flag)" : "var(--allow-line)"
                }`,
                background: gone
                  ? "var(--block-soft)"
                  : isAltered
                    ? "var(--flag-soft)"
                    : "var(--allow-soft)",
                transition:
                  "border-color var(--d) var(--e-out), background var(--d) var(--e-out)",
              }}
            />
            {i < CHAIN_LINKS - 1 ? (
              <span
                aria-hidden="true"
                style={{
                  display: "block",
                  width: 10,
                  height: 1.5,
                  background:
                    i >= 2 && broken > i - 2 ? "var(--block)" : "var(--allow-line)",
                  // The link visibly parts rather than just recolouring.
                  transform: i >= 2 && broken > i - 2 ? "scaleX(0.35)" : "none",
                  transformOrigin: "left center",
                  transition:
                    "transform var(--d-slow) var(--e-out), background var(--d) var(--e-out)",
                }}
              />
            ) : null}
          </div>
        );
      })}
      <span className="ml-2 text-[10.5px] text-[var(--block)]">
        every later record fails
      </span>
    </div>
  );
}
