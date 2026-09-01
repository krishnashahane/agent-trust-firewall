"use client";

import { useCallback, useEffect, useState } from "react";
import {
  BandLabel,
  Button,
  EmptyState,
  IntelChip,
  LoadingRegion,
  Panel,
  ScoreMeter,
  Skeleton,
  Stat,
  VerdictBadge,
  relativeTime,
} from "@/components/ui";
import { Counter } from "@/components/motion";
import { Sparkline } from "@/components/Sparkline";
import { CopyValue } from "@/components/CopyValue";
import type { PolicyViolation, RiskBand, Verdict } from "@/lib/atf/types";

interface Event {
  id: string;
  agentId: string;
  agentName: string;
  tool: string;
  destination: string;
  verdict: Verdict;
  score: number;
  band: RiskBand;
  topSignals: { id: string; label: string; points: number }[];
  violations: PolicyViolation[];
  explanation: string;
  sealedFieldCount: number;
  intelLabels: string[];
  intelLive: boolean;
  timestamp: number;
}

interface Summary {
  total: number;
  allowed: number;
  flagged: number;
  blocked: number;
  sealedFields: number;
}

type Filter = "all" | "BLOCK" | "FLAG" | "ALLOW";

const POLL_MS = 4000;

const FILTERS: { value: Filter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "BLOCK", label: "Blocked" },
  { value: "FLAG", label: "Flagged" },
  { value: "ALLOW", label: "Allowed" },
];

export function TrafficConsole() {
  const [events, setEvents] = useState<Event[] | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/traffic?limit=150", { cache: "no-store" });
      if (!response.ok) throw new Error("traffic");
      const data = (await response.json()) as { events: Event[]; summary: Summary };
      setEvents(data.events);
      setSummary(data.summary);
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    // Deferred out of the effect commit; the loader sets state.
    const first = setTimeout(() => void load(), 0);
    const poll = setInterval(() => void load(), POLL_MS);
    // Relative timestamps go stale between polls, so tick them separately.
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      clearTimeout(first);
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [load]);

  const loading = events === null && !error;
  const shown =
    events === null ? [] : filter === "all" ? events : events.filter((e) => e.verdict === filter);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Stat
          label="Calls shown"
          value={summary ? <Counter value={summary.total} /> : "—"}
          hint="most recent, intercepted and decided"
        />
        <Stat
          label="Allowed"
          value={summary ? <Counter value={summary.allowed} /> : "—"}
          tone="allow"
        />
        <Stat
          label="Flagged"
          value={summary ? <Counter value={summary.flagged} /> : "—"}
          tone="flag"
        />
        <Stat
          label="Blocked"
          value={summary ? <Counter value={summary.blocked} /> : "—"}
          tone="block"
        />
        <Stat
          label="Sealed fields"
          value={summary ? <Counter value={summary.sealedFields} /> : "—"}
          tone="seal"
          hint="encrypted to destination"
        />
      </div>

      {events && events.length >= 2 ? (
        <Panel
          title="Risk over time"
          caption="Every score the engine produced in this window, oldest to newest. A single number hides whether risk is climbing."
        >
          <div className="flex flex-wrap items-end justify-between gap-4 px-4 py-4 sm:px-5">
            <Sparkline
              // listEvents returns newest-first; a trend reads left-to-right.
              values={[...events].reverse().map((e) => e.score)}
              width={520}
              height={54}
              color="var(--accent)"
              label={`Risk scores for the last ${events.length} intercepted calls, oldest to newest.`}
            />
            <dl className="flex gap-5 text-[11px]">
              <div>
                <dt className="text-[var(--text-faint)]">Peak</dt>
                <dd className="tnum mt-0.5 text-[15px] font-semibold">
                  {Math.max(...events.map((e) => e.score)).toFixed(0)}
                </dd>
              </div>
              <div>
                <dt className="text-[var(--text-faint)]">Median</dt>
                <dd className="tnum mt-0.5 text-[15px] font-semibold">
                  {(() => {
                    const sorted = [...events].map((e) => e.score).sort((a, b) => a - b);
                    const mid = Math.floor(sorted.length / 2);
                    const median =
                      sorted.length % 2 === 0
                        ? ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2
                        : (sorted[mid] ?? 0);
                    return median.toFixed(0);
                  })()}
                </dd>
              </div>
            </dl>
          </div>
        </Panel>
      ) : null}

      <Panel
        title="Live traffic"
        caption="Every call the firewall intercepted, newest first. Select a row to see exactly how its score was reached."
        action={
          <div
            role="tablist"
            aria-label="Filter traffic by verdict"
            className="flex items-center gap-0.5 rounded-[var(--r)] bg-[var(--bg-sunken)] p-0.5"
          >
            {FILTERS.map((option) => {
              const active = filter === option.value;
              return (
                <button
                  key={option.value}
                  role="tab"
                  type="button"
                  aria-selected={active}
                  onClick={() => setFilter(option.value)}
                  className={`tap rounded-[var(--r-sm)] px-2.5 py-1 text-[11.5px] font-medium transition-colors duration-[var(--d-fast)] ${
                    active
                      ? "bg-[var(--bg-raised)] text-[var(--text)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-muted)] hover:text-[var(--text)]"
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
        }
      >
        {loading ? (
          <LoadingRegion label="Loading intercepted traffic">
            <ul className="divide-y divide-[var(--border)]">
              {Array.from({ length: 8 }, (_, i) => (
                <li key={i} className="flex items-center gap-4 px-4 py-3.5 sm:px-5">
                  <Skeleton width={68} height={20} style={{ borderRadius: 999 }} />
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <Skeleton width={`${38 + ((i * 7) % 22)}%`} height={11} />
                    <Skeleton width={`${26 + ((i * 5) % 18)}%`} height={9} />
                  </div>
                  <Skeleton width={72} height={6} className="hidden sm:block" />
                  <Skeleton width={44} height={9} />
                </li>
              ))}
            </ul>
          </LoadingRegion>
        ) : error ? (
          <EmptyState
            tone="error"
            title="Could not reach the firewall"
            body="The traffic endpoint did not respond. This page retries every few seconds on its own."
            action={
              <Button size="sm" variant="secondary" onClick={() => void load()}>
                Retry now
              </Button>
            }
          />
        ) : shown.length === 0 ? (
          <EmptyState
            title={filter === "all" ? "No traffic yet" : "Nothing matches this filter"}
            body={
              filter === "all"
                ? "The demo fleet seeds traffic at boot, so this should fill in within a few seconds. Run a scenario in the attack range to add one immediately."
                : "No call in the current window had this verdict. The attack range can produce one on demand."
            }
            action={
              <Button size="sm" variant="secondary" href="/console/attack-range">
                Open the attack range
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {shown.map((event) => {
              const open = expanded === event.id;
              return (
                <li key={event.id}>
                  <button
                    type="button"
                    onClick={() => setExpanded(open ? null : event.id)}
                    aria-expanded={open}
                    className="row-hover flex w-full flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 text-left sm:px-5"
                  >
                    <span className="w-[76px] shrink-0">
                      <VerdictBadge verdict={event.verdict} size="sm" />
                    </span>

                    <span className="min-w-0 flex-1">
                      <span className="mono block truncate text-[12.5px] font-medium">
                        {event.tool}
                      </span>
                      <span className="mt-0.5 block truncate text-[11.5px] text-[var(--text-muted)]">
                        {event.agentName} → {event.destination}
                      </span>
                    </span>

                    {event.intelLive && event.intelLabels.length > 0 ? (
                      <span className="hidden shrink-0 lg:block">
                        <IntelChip live labels={event.intelLabels} />
                      </span>
                    ) : null}

                    {event.sealedFieldCount > 0 ? (
                      <span
                        className="hidden shrink-0 rounded-full px-1.5 py-0.5 text-[10.5px] font-medium sm:block"
                        style={{ background: "var(--seal-soft)", color: "var(--seal)" }}
                        title="Carried fields encrypted to the destination, which the firewall cannot read."
                      >
                        {event.sealedFieldCount} sealed
                      </span>
                    ) : null}

                    <span className="hidden shrink-0 sm:block">
                      <ScoreMeter score={event.score} band={event.band} />
                    </span>

                    <span className="mono w-[58px] shrink-0 text-right text-[11px] text-[var(--text-faint)]">
                      {relativeTime(event.timestamp, now)}
                    </span>

                    <span
                      aria-hidden="true"
                      className="hidden shrink-0 text-[var(--text-faint)] sm:block"
                      style={{
                        transform: open ? "rotate(90deg)" : "none",
                        transition: "transform var(--d) var(--e-out)",
                      }}
                    >
                      ›
                    </span>
                  </button>

                  {/* Grid-rows transition gives a real height animation without
                   * measuring the content, so expanding never jumps. */}
                  <div
                    className="grid"
                    style={{
                      gridTemplateRows: open ? "1fr" : "0fr",
                      transition: "grid-template-rows var(--d-slow) var(--e-out)",
                    }}
                  >
                    <div className="overflow-hidden">
                      <div className="border-t border-[var(--border)] bg-[var(--bg-inset)] px-4 py-4 sm:px-5">
                        <p className="text-[12.5px] leading-relaxed">
                          {event.explanation}
                        </p>

                        {event.violations.length > 0 ? (
                          <div className="mt-4">
                            <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--block)]">
                              Hard rules broken
                            </h4>
                            <ul className="mt-2 space-y-1.5">
                              {event.violations.map((violation) => (
                                <li
                                  key={violation.rule}
                                  className="text-[12px] leading-relaxed text-[var(--text-muted)]"
                                >
                                  <span className="mono text-[var(--block)]">
                                    {violation.rule}
                                  </span>{" "}
                                  — {violation.detail}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ) : null}

                        <div className="mt-4">
                          <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
                            What drove the score
                          </h4>
                          <ul className="mt-2 space-y-1.5">
                            {event.topSignals.length === 0 ? (
                              <li className="text-[12px] text-[var(--text-muted)]">
                                Nothing scored above zero — this call was unremarkable
                                on every dimension.
                              </li>
                            ) : (
                              event.topSignals.map((signal) => (
                                <li key={signal.id} className="flex items-center gap-3 text-[12px]">
                                  <span className="w-32 shrink-0 text-[var(--text-muted)]">
                                    {signal.label}
                                  </span>
                                  <span className="h-1 max-w-[160px] flex-1 overflow-hidden rounded-full bg-[var(--bg-sunken)]">
                                    <span
                                      className="block h-full rounded-full bg-[var(--accent)]"
                                      style={{
                                        width: open
                                          ? `${Math.min(100, signal.points * 2.2)}%`
                                          : "0%",
                                        transition: "width var(--d-slow) var(--e-out)",
                                      }}
                                    />
                                  </span>
                                  <span className="mono tnum text-[var(--text-faint)]">
                                    +{signal.points.toFixed(1)}
                                  </span>
                                </li>
                              ))
                            )}
                          </ul>
                        </div>

                        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-[11px] text-[var(--text-faint)]">
                          <BandLabel band={event.band} />
                          <IntelChip live={event.intelLive} labels={event.intelLabels} />
                          <span className="inline-flex items-center gap-1">
                            audit
                            <CopyValue
                              value={event.id}
                              display={`${event.id.slice(0, 12)}…`}
                              title="audit record id"
                            />
                          </span>
                          <span className="mono">agent {event.agentId}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </div>
  );
}
