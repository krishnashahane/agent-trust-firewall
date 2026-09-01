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
 * The scenarios this card may run.
 *
 * Picked at random per load rather than always showing the same forged-identity
 * example. Two reasons: a visitor returning to the page previously saw the
 * identical call every time, which reads as scripted no matter how genuinely
 * the verdict is recomputed; and one of these is deliberately *not* an attack,
 * so the card is not simply a machine that always says "blocked".
 */
const ROTATION = [
  "unenrolled",
  "replay",
  "escalation",
  "revoked",
  "injection",
  "healthy",
] as const;

/**
 * The live interception card.
 *
 * A real attack run against the real engine. Nothing is pre-recorded and no
 * outcome is asserted in advance: if the firewall ever failed to block a forged
 * identity, this card would say so on the front page.
 *
 * Motion behaviour is deliberate. Auto-playing content with no way to stop it
 * fails WCAG 2.2.2, so there is an explicit pause control, and anyone who has
 * asked their system for reduced motion gets the finished result immediately
 * with no sequence at all.
 */
export function LiveHeroDemo() {
  const reduced = useReducedMotion();
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [phase, setPhase] = useState<"running" | "done" | "error">("running");
  const [runId, setRunId] = useState(0);
  const [paused, setPaused] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  /**
   * Chosen once per mount so a re-render cannot swap the scenario mid-run.
   *
   * Picked in the effect rather than in a ref initialiser: the choice is random,
   * so doing it during render would both be impure and let the server and the
   * client disagree about which scenario this is — a hydration mismatch.
   */
  const scenarioRef = useRef<string>(ROTATION[0]);

  // Checks land on a timer; the verdict waits for both the timer and the fetch,
  // so a fast response never skips the sequence and a slow one never truncates.
  const landed = useSequence(CHECKS.length, { runId, stepMs: 300, startDelay: 260 });

  const run = useCallback(async (scenario: string) => {
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
        body: JSON.stringify({ scenario }),
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
    const timer = setTimeout(() => {
      scenarioRef.current =
        (ROTATION[Math.floor(Math.random() * ROTATION.length)] as string) ??
        ROTATION[0];
      void run(scenarioRef.current);
    }, 0);
    return () => {
      clearTimeout(timer);
      abortRef.current?.abort();
    };
  }, [run]);

  /** Run a different scenario than the one just shown, where possible. */
  const runNext = useCallback(() => {
    const others = ROTATION.filter((id) => id !== scenarioRef.current);
    const next = (others[Math.floor(Math.random() * others.length)] ??
      scenarioRef.current) as string;
    scenarioRef.current = next;
    setPaused(false);
    void run(next);
  }, [run]);

  const decision = outcome?.decision;
  // Pausing freezes the reveal where it is; the data is already correct
  // underneath, so nothing is lost by stopping the animation.
  const sequenceComplete = reduced || paused || landed >= CHECKS.length;
  const showVerdict = phase === "done" && decision && sequenceComplete;
  const landedNow = paused ? CHECKS.length : landed;

  return (
    <div className="panel overflow-hidden" style={{ boxShadow: "var(--shadow)" }}>
      <header className="flex items-center justify-between gap-3 border-b border-[var(--border)] bg-[var(--bg-inset)] px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={paused || reduced ? "h-1.5 w-1.5 rounded-full" : "live-dot h-1.5 w-1.5 rounded-full"}
            style={{
              background: showVerdict
                ? decision.verdict === "ALLOW"
                  ? "var(--allow)"
                  : "var(--block)"
                : "var(--accent)",
            }}
          />
          <span className="truncate text-[11px] font-medium uppercase tracking-[0.07em] text-[var(--text-muted)]">
            Live interception
          </span>
        </div>

        <div className="flex shrink-0 items-center gap-0.5">
          {/* WCAG 2.2.2: content that starts moving on its own must be
            * stoppable. Hidden when motion is already off, since there is then
            * nothing playing to pause. */}
          {!reduced ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPaused((p) => !p)}
              ariaLabel={paused ? "Resume the animation" : "Pause the animation"}
            >
              {paused ? "Resume" : "Pause"}
            </Button>
          ) : null}
          <Button
            size="sm"
            variant="ghost"
            onClick={runNext}
            disabled={phase === "running"}
          >
            New call
          </Button>
        </div>
      </header>

      <div className="px-4 py-4 sm:px-5">
        <dl className="mono space-y-1 text-[11.5px] leading-relaxed">
          <div className="flex gap-2">
            <dt className="w-12 shrink-0 text-[var(--text-faint)]">agent</dt>
            <dd className="min-w-0 truncate">
              {outcome ? outcome.scenario.title : "…"}
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-12 shrink-0 text-[var(--text-faint)]">calls</dt>
            <dd className="min-w-0 truncate">
              {decision ? decision.risk.contributions.length : 7} signals scored
            </dd>
          </div>
          {outcome?.intel ? (
            <div className="flex gap-2">
              <dt className="w-12 shrink-0 text-[var(--text-faint)]">from</dt>
              <dd className="min-w-0 truncate">{outcome.intel.ip}</dd>
            </div>
          ) : null}
        </dl>

        <ul className="mt-4 space-y-2">
          {CHECKS.map((check, index) => {
            const done = landedNow > index;
            // Which check fails is read from the decision, never hardcoded.
            const failed =
              done &&
              showVerdict &&
              ((index === 1 &&
                decision.violations.some(
                  (v) => v.rule === "unknown-agent" || v.rule === "identity-unproven",
                )) ||
                (index === 2 &&
                  decision.violations.some((v) => v.rule.startsWith("capability"))));

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
          aria-live="polite"
          className="mt-4 rounded-[var(--r)] border px-3.5 py-3"
          style={{
            borderColor: showVerdict
              ? decision.verdict === "ALLOW"
                ? "var(--allow-line)"
                : "var(--block-line)"
              : "var(--border)",
            background: showVerdict
              ? decision.verdict === "ALLOW"
                ? "var(--allow-soft)"
                : "var(--block-soft)"
              : "var(--bg-inset)",
            transition:
              "background var(--d-slow) var(--e-out), border-color var(--d-slow) var(--e-out)",
          }}
        >
          {phase === "error" ? (
            <p className="text-[12px] leading-relaxed text-[var(--text-muted)]">
              The demo could not reach the engine.{" "}
              <button
                type="button"
                onClick={runNext}
                className="text-[var(--accent)] underline underline-offset-2"
              >
                Try again
              </button>
              .
            </p>
          ) : showVerdict ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <VerdictBadge verdict={decision.verdict} animate={!paused} />
                <ScoreMeter score={decision.risk.score} band={decision.risk.band} />
              </div>
              <p className="mt-2.5 text-[12.5px] leading-relaxed text-[var(--text)]">
                {decision.explanation}
              </p>
              {outcome?.intel ? (
                <div className="mt-2.5">
                  <IntelChip live={outcome.intel.live} labels={outcome.intel.labels} />
                </div>
              ) : null}
            </>
          ) : (
            <p className="text-[12px] text-[var(--text-faint)]">Verifying the call…</p>
          )}
        </div>
      </div>
    </div>
  );
}
