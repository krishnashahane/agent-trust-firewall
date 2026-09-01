"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  Button,
  EmptyState,
  LoadingRegion,
  Panel,
  ScoreMeter,
  Skeleton,
  VerdictBadge,
} from "@/components/ui";
import { useReducedMotion, useSequence } from "@/components/motion";
import { IntelPanel } from "@/components/IntelPanel";
import type { Decision, IpIntel } from "@/lib/atf/types";

interface Scenario {
  id: string;
  title: string;
  attack: string;
  defence: string;
  hostile: boolean;
}

interface Outcome {
  scenario: Scenario;
  decision: Decision;
  precedingCalls: number;
  intel: IpIntel | null;
}

/**
 * The attack range.
 *
 * The result panel used to render its final state the instant a scenario
 * returned, which undersold the most technically credible content on the site —
 * real per-signal scoring with real point contributions. Now the verdict lands
 * first, then the score bar fills, then the hard-rule callout, then the signals
 * stagger in one row at a time with their bars filling on entry.
 *
 * Every number and every reasoning string is exactly what the engine returned;
 * only the order of appearance is choreographed.
 */
export function AttackRange() {
  const params = useSearchParams();
  const preselected = params.get("scenario");
  const reduced = useReducedMotion();

  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [selected, setSelected] = useState<string | null>(preselected);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState(0);
  const autoRan = useRef<string | null>(null);

  const signalCount = outcome?.decision.risk.contributions.length ?? 0;
  // Stage 1 = verdict, 2 = score, 3 = violations, then one per signal row.
  const revealed = useSequence(3 + signalCount, {
    runId,
    stepMs: 90,
    startDelay: 60,
  });

  useEffect(() => {
    const first = setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch("/api/simulate", { cache: "no-store" });
          if (!response.ok) throw new Error();
          const data = (await response.json()) as { scenarios: Scenario[] };
          setScenarios(data.scenarios);
        } catch {
          setError("Could not load the scenario catalogue.");
          setScenarios([]);
        }
      })();
    }, 0);
    return () => clearTimeout(first);
  }, []);

  const run = useCallback(async (id: string) => {
    setRunning(true);
    setError(null);
    setSelected(id);
    setOutcome(null);
    try {
      const response = await fetch("/api/simulate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scenario: id }),
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "The firewall rejected the request.");
      }
      setOutcome((await response.json()) as Outcome);
      setRunId((n) => n + 1);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setRunning(false);
    }
  }, []);

  // A deep link from the landing page should land on a result, not a menu.
  useEffect(() => {
    if (!preselected || !scenarios || autoRan.current === preselected) return;
    if (!scenarios.some((s) => s.id === preselected)) return;
    autoRan.current = preselected;
    const timer = setTimeout(() => void run(preselected), 0);
    return () => clearTimeout(timer);
  }, [preselected, scenarios, run]);

  const at = (stage: number) => reduced || revealed >= stage;

  return (
    <div className="grid gap-4 lg:grid-cols-[340px_1fr] lg:items-start">
      <Panel
        title="Adversaries"
        caption="Each is built for real and sent through the live firewall. Nothing is pre-scripted."
      >
        {scenarios === null ? (
          <LoadingRegion label="Loading adversaries">
            <ul className="divide-y divide-[var(--border)]">
              {Array.from({ length: 6 }, (_, i) => (
                <li key={i} className="space-y-2 px-4 py-3.5 sm:px-5">
                  <Skeleton width={`${44 + ((i * 9) % 26)}%`} height={12} />
                  <Skeleton width="86%" height={9} />
                </li>
              ))}
            </ul>
          </LoadingRegion>
        ) : scenarios.length === 0 ? (
          <EmptyState
            tone="error"
            title="Catalogue unavailable"
            body="The engine did not return its scenario list. Reload the page to try again."
          />
        ) : (
          <ul role="list" className="divide-y divide-[var(--border)]">
            {scenarios.map((scenario) => {
              const active = selected === scenario.id;
              return (
                <li key={scenario.id}>
                  <button
                    type="button"
                    onClick={() => void run(scenario.id)}
                    disabled={running}
                    aria-pressed={active}
                    className={`w-full px-4 py-3.5 text-left transition-colors duration-[var(--d-fast)] disabled:opacity-60 sm:px-5 ${
                      active ? "bg-[var(--accent-soft)]" : "hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{
                          background: scenario.hostile ? "var(--block)" : "var(--allow)",
                        }}
                      />
                      <span
                        className={`text-[13px] ${
                          active ? "font-semibold text-[var(--accent)]" : "font-medium"
                        }`}
                      >
                        {scenario.title}
                      </span>
                    </span>
                    <span className="mt-1 block text-[12px] leading-relaxed text-[var(--text-muted)]">
                      {scenario.attack}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Panel
        title="Result"
        caption="The verdict the engine actually returned, and the reasoning behind it."
      >
        {error ? (
          <EmptyState tone="error" title="That did not run" body={error} />
        ) : running ? (
          <LoadingRegion label="Running the attack">
            <div className="space-y-4 px-4 py-5 sm:px-5">
              <div className="flex items-center justify-between gap-3">
                <Skeleton width="42%" height={16} />
                <Skeleton width={78} height={22} style={{ borderRadius: 999 }} />
              </div>
              <Skeleton width="100%" height={74} style={{ borderRadius: 8 }} />
              <div className="space-y-2.5">
                {Array.from({ length: 5 }, (_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton width={`${30 + ((i * 11) % 24)}%`} height={10} />
                    <Skeleton width="100%" height={4} />
                  </div>
                ))}
              </div>
              <p className="text-[12px] text-[var(--text-faint)]">
                Issuing a challenge, building the proof, and submitting it through the
                same path production traffic uses.
              </p>
            </div>
          </LoadingRegion>
        ) : !outcome ? (
          <EmptyState
            title="Pick an adversary"
            body="Choose one from the list. The firewall will verify it, score it against live threat intelligence, and say in plain language what it decided and why."
          />
        ) : (
          <div className="px-4 py-5 sm:px-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-[15px] font-semibold">{outcome.scenario.title}</h3>
                <p className="mt-1 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                  {outcome.scenario.attack}
                </p>
              </div>
              <div
                style={{
                  opacity: at(1) ? 1 : 0,
                  transition: "opacity var(--d) var(--e-out)",
                }}
              >
                {at(1) ? <VerdictBadge verdict={outcome.decision.verdict} animate /> : null}
              </div>
            </div>

            <div
              className="mt-4 rounded-[var(--r)] border px-4 py-3.5"
              style={{
                borderColor:
                  outcome.decision.verdict === "BLOCK"
                    ? "var(--block-line)"
                    : "var(--border)",
                background:
                  outcome.decision.verdict === "BLOCK"
                    ? "var(--block-soft)"
                    : "var(--bg-inset)",
              }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
                  Risk score
                </span>
                <ScoreMeter
                  score={at(2) ? outcome.decision.risk.score : 0}
                  band={outcome.decision.risk.band}
                  width={96}
                />
              </div>
              <p className="mt-2.5 text-[12.5px] leading-relaxed">
                {outcome.decision.explanation}
              </p>
              {outcome.decision.violations.length > 0 ? (
                <p className="mt-2 text-[12px] leading-relaxed text-[var(--text-muted)]">
                  Note the score is low — it is not what stopped this call. A hard rule
                  was broken, and those block at any score.
                </p>
              ) : null}
            </div>

            {outcome.precedingCalls > 0 ? (
              <p className="mt-3 text-[12px] text-[var(--text-faint)]">
                This scenario made {outcome.precedingCalls} real preceding call
                {outcome.precedingCalls === 1 ? "" : "s"} to set the conditions up —
                they appear in the console traffic too.
              </p>
            ) : null}

            {outcome.decision.violations.length > 0 ? (
              <div
                className="mt-5"
                style={{
                  opacity: at(3) ? 1 : 0,
                  transform: at(3) ? "none" : "translate3d(0,6px,0)",
                  transition:
                    "opacity var(--d-slow) var(--e-out), transform var(--d-slow) var(--e-out)",
                }}
              >
                <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--block)]">
                  Hard rules broken
                </h4>
                <ul className="mt-2 space-y-2">
                  {outcome.decision.violations.map((violation) => (
                    <li
                      key={violation.rule}
                      className="rounded-[var(--r)] border px-3.5 py-2.5"
                      style={{
                        borderColor: "var(--block-line)",
                        background: "var(--block-soft)",
                      }}
                    >
                      <span className="mono text-[11px] font-semibold text-[var(--block)]">
                        {violation.rule}
                      </span>
                      <p className="mt-1 text-[12px] leading-relaxed text-[var(--text)]">
                        {violation.detail}
                      </p>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div className="mt-5">
              <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
                Every signal, and what it saw
              </h4>
              <ul className="mt-2 divide-y divide-[var(--border)] overflow-hidden rounded-[var(--r)] border border-[var(--border)]">
                {outcome.decision.risk.contributions.map((contribution, index) => {
                  const shown = at(4 + index);
                  return (
                    <li
                      key={contribution.id}
                      className="px-3.5 py-2.5"
                      style={{
                        opacity: shown ? 1 : 0,
                        transform: shown ? "none" : "translate3d(0,6px,0)",
                        transition:
                          "opacity var(--d) var(--e-out), transform var(--d) var(--e-out)",
                      }}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[12px] font-medium">{contribution.label}</span>
                        <span className="mono tnum shrink-0 text-[11px] text-[var(--text-faint)]">
                          +{contribution.points.toFixed(1)} pts
                        </span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-[var(--bg-sunken)]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: shown
                              ? `${Math.min(100, contribution.score * 100)}%`
                              : "0%",
                            background:
                              contribution.score > 0.6
                                ? "var(--block)"
                                : contribution.score > 0.3
                                  ? "var(--flag)"
                                  : "var(--allow)",
                            transition: "width var(--d-slow) var(--e-out)",
                          }}
                        />
                      </div>
                      <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--text-muted)]">
                        {contribution.evidence}
                      </p>
                    </li>
                  );
                })}
              </ul>
            </div>

            {outcome.intel ? (
              <div className="mt-5">
                <IntelPanel intel={outcome.intel} />
              </div>
            ) : null}

            <div className="mt-5 rounded-[var(--r)] border border-[var(--border)] px-3.5 py-3">
              <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
                What was supposed to catch it
              </h4>
              <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--text-muted)]">
                {outcome.scenario.defence}
              </p>
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <span className="mono text-[11px] text-[var(--text-faint)]">
                audit record {outcome.decision.auditId}
              </span>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void run(outcome.scenario.id)}
                disabled={running}
              >
                Run again
              </Button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
