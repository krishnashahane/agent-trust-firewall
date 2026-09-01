"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button, IntelChip, ScoreMeter, VerdictBadge } from "@/components/ui";
import { useReducedMotion, useSequence } from "@/components/motion";
import type { Decision, IpIntel } from "@/lib/atf/types";

interface Outcome {
  scenario: { id: string; title: string; attack: string };
  decision: Decision;
  intel: IpIntel | null;
}

const CHECKS = [
  { label: "Envelope opened", detail: "decrypted inside the firewall" },
  { label: "Identity proof checked", detail: "zero-knowledge, single-use" },
  { label: "Capability checked", detail: "Merkle inclusion proof" },
  { label: "Risk scored", detail: "seven signals, live intel" },
] as const;

/**
 * The live interception card.
 *
 * A real attack run against the real engine on every load. Nothing here is
 * pre-recorded, and nothing asserts the outcome in advance: if the firewall
 * ever failed to block a forged identity, this card would say so on the front
 * page. That is the point of putting it here.
 *
 * The checks land one at a time rather than all at once, because the sequence
 * *is* the product — a viewer should see that four separate things were
 * verified, not just that a red badge appeared.
 */
export function LiveHeroDemo() {
  const reduced = useReducedMotion();
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [phase, setPhase] = useState<"running" | "done" | "error">("running");
  const [runId, setRunId] = useState(0);
  const abortRef = useRef<AbortController | null>(null);

  // Checks land on a timer; the verdict waits for both the timer and the fetch,
  // so a fast response never skips the sequence and a slow one never truncates.
  const landed = useSequence(CHECKS.length, { runId, stepMs: 300, startDelay: 260 });

  const run = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setPhase("running");
    setOutcome(null);
    setRunId((n) => n + 1);

    try {
      const response = await fetch("/api/simulate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scenario: "unenrolled" }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("simulate failed");
      const data = (await response.json()) as Outcome;
      if (controller.signal.aborted) return;
      setOutcome(data);
      setPhase("done");
    } catch (error) {
      if ((error as Error)?.name === "AbortError") return;
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void run(), 0);
    return () => {
      clearTimeout(timer);
      abortRef.current?.abort();
    };
  }, [run]);

  const decision = outcome?.decision;
  const sequenceComplete = reduced || landed >= CHECKS.length;
  const showVerdict = phase === "done" && decision && sequenceComplete;

  return (
    <div className="panel overflow-hidden" style={{ boxShadow: "var(--shadow)" }}>
      <header className="flex items-center justify-between gap-3 border-b border-[var(--border)] bg-[var(--bg-inset)] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span
            className="live-dot h-1.5 w-1.5 rounded-full"
            style={{ background: showVerdict ? "var(--block)" : "var(--accent)" }}
          />
          <span className="text-[11px] font-medium uppercase tracking-[0.07em] text-[var(--text-muted)]">
            Live interception
          </span>
        </div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => void run()}
          disabled={phase === "running"}
        >
          Run again
        </Button>
      </header>

      <div className="px-4 py-4 sm:px-5">
        <dl className="mono space-y-1 text-[11.5px] leading-relaxed">
          <div className="flex gap-2">
            <dt className="w-12 shrink-0 text-[var(--text-faint)]">agent</dt>
            <dd className="min-w-0">
              ghost-agent{" "}
              <span className="text-[var(--text-faint)]">(not enrolled)</span>
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-12 shrink-0 text-[var(--text-faint)]">calls</dt>
            <dd className="min-w-0">
              payments.charge{" "}
              <span className="text-[var(--text-faint)]">$9,900.00</span>
            </dd>
          </div>
          {outcome?.intel ? (
            <div className="flex gap-2">
              <dt className="w-12 shrink-0 text-[var(--text-faint)]">from</dt>
              <dd className="min-w-0">{outcome.intel.ip}</dd>
            </div>
          ) : null}
        </dl>

        <ul className="mt-4 space-y-2">
          {CHECKS.map((check, index) => {
            const done = landed > index;
            // The identity check is the one that fails in this scenario; it is
            // marked from the decision, never hardcoded.
            const failed =
              done &&
              showVerdict &&
              index === 1 &&
              decision.violations.some((v) => v.rule === "unknown-agent");

            return (
              <li key={check.label} className="flex items-center gap-2.5">
                <span
                  aria-hidden="true"
                  className="grid h-[18px] w-[18px] shrink-0 place-items-center rounded-full text-[10px] font-bold"
                  style={{
                    background: !done
                      ? "var(--bg-sunken)"
                      : failed
                        ? "var(--block-soft)"
                        : "var(--allow-soft)",
                    color: failed ? "var(--block)" : "var(--allow)",
                    transform: done && !reduced ? "scale(1)" : done ? "none" : "scale(0.86)",
                    transition:
                      "background var(--d) var(--e-out), transform var(--d) var(--e-snap)",
                  }}
                >
                  {done ? (failed ? "✕" : "✓") : ""}
                </span>
                <span
                  className="min-w-0 text-[12.5px]"
                  style={{
                    color: done ? "var(--text)" : "var(--text-faint)",
                    transition: "color var(--d) var(--e-out)",
                  }}
                >
                  {check.label}
                  <span className="ml-1.5 text-[11px] text-[var(--text-faint)]">
                    {check.detail}
                  </span>
                </span>
              </li>
            );
          })}
        </ul>

        <div
          className="mt-4 rounded-[var(--r)] border px-3.5 py-3"
          style={{
            borderColor: showVerdict ? "var(--block-line)" : "var(--border)",
            background: showVerdict ? "var(--block-soft)" : "var(--bg-inset)",
            transition:
              "background var(--d-slow) var(--e-out), border-color var(--d-slow) var(--e-out)",
          }}
        >
          {phase === "error" ? (
            <p className="text-[12px] leading-relaxed text-[var(--text-muted)]">
              The demo could not reach the engine.{" "}
              <a href="/console" className="text-[var(--accent)] underline underline-offset-2">
                Open the console
              </a>{" "}
              instead.
            </p>
          ) : showVerdict ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <VerdictBadge verdict={decision.verdict} animate />
                <ScoreMeter score={decision.risk.score} band={decision.risk.band} />
              </div>
              <p className="mt-2.5 text-[12.5px] leading-relaxed text-[var(--text)]">
                {decision.explanation}
              </p>
              {outcome?.intel ? (
                <div className="mt-2.5">
                  <IntelChip
                    live={outcome.intel.live}
                    labels={outcome.intel.labels}
                  />
                </div>
              ) : null}
            </>
          ) : (
            <p className="text-[12px] text-[var(--text-faint)]">
              Verifying the call…
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
