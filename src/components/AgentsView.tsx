"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Button,
  EmptyState,
  IntelChip,
  LoadingRegion,
  Panel,
  Skeleton,
  relativeTime,
} from "@/components/ui";
import { Counter } from "@/components/motion";
import type { Verdict } from "@/lib/atf/types";

interface AgentIntel {
  live: boolean;
  threat: number;
  labels: string[];
  providers: {
    provider: string;
    origin: "live" | "live-clean" | "unavailable";
    evidence: string;
    reference: string | null;
  }[];
}

interface AgentRow {
  agentId: string;
  displayName: string;
  capabilities: string[];
  capabilityRoot: string;
  registeredAt: number;
  keyRotatedAt: number;
  revoked: boolean;
  revocationReason: string | null;
  calls: number;
  blocked: number;
  flagged: number;
  trustScore: number;
  originIp: string | null;
  intel: AgentIntel | null;
  recent: { verdict: Verdict; score: number }[];
}

const VERDICT_COLOR: Record<Verdict, string> = {
  ALLOW: "var(--allow)",
  FLAG: "var(--flag)",
  BLOCK: "var(--block)",
};

export function AgentsView() {
  const [agents, setAgents] = useState<AgentRow[] | null>(null);
  const [error, setError] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/agents", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const data = (await response.json()) as { agents: AgentRow[] };
      setAgents(data.agents);
      setNow(Date.now());
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    // Deferred out of the effect commit; the loader sets state.
    const first = setTimeout(() => void load(), 0);
    const poll = setInterval(() => void load(), 8000);
    return () => {
      clearTimeout(first);
      clearInterval(poll);
    };
  }, [load]);

  return (
    <Panel
      title="Enrolled agents"
      caption="Every agent the firewall knows about. Trust is the inverse of recent risk; the intel chip reports what public threat intelligence says about the address each one calls from."
    >
      {error ? (
        <EmptyState
          tone="error"
          title="Could not load agents"
          body="The registry endpoint did not respond. This page retries on its own."
          action={
            <Button size="sm" variant="secondary" onClick={() => void load()}>
              Retry now
            </Button>
          }
        />
      ) : agents === null ? (
        <LoadingRegion label="Loading the enrolled fleet">
          <ul className="divide-y divide-[var(--border)]">
            {Array.from({ length: 5 }, (_, i) => (
              <li key={i} className="px-4 py-4 sm:px-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1 space-y-2">
                    <Skeleton width={`${30 + ((i * 8) % 20)}%`} height={13} />
                    <Skeleton width="26%" height={10} />
                    <div className="flex gap-1.5 pt-1">
                      <Skeleton width={68} height={18} style={{ borderRadius: 4 }} />
                      <Skeleton width={82} height={18} style={{ borderRadius: 4 }} />
                    </div>
                  </div>
                  <Skeleton width={40} height={28} />
                </div>
              </li>
            ))}
          </ul>
        </LoadingRegion>
      ) : agents.length === 0 ? (
        <EmptyState
          title="No agents enrolled"
          body="Agents enrol by submitting a public key and a commitment to their capability set. The demo fleet enrols itself at boot."
        />
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {agents.map((agent) => {
            const open = expanded === agent.agentId;
            const trustColor =
              agent.trustScore >= 70
                ? "var(--allow)"
                : agent.trustScore >= 45
                  ? "var(--flag)"
                  : "var(--block)";

            return (
              <li key={agent.agentId} className="px-4 py-4 sm:px-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-[13.5px] font-semibold">{agent.displayName}</h3>
                      {agent.revoked ? (
                        <span
                          className="rounded-full border px-1.5 py-[1px] text-[10px] font-semibold uppercase tracking-wide"
                          style={{
                            background: "var(--block-soft)",
                            color: "var(--block)",
                            borderColor: "var(--block-line)",
                          }}
                        >
                          Revoked
                        </span>
                      ) : null}
                    </div>

                    <p className="mono mt-0.5 text-[11px] text-[var(--text-faint)]">
                      {agent.agentId}
                      {agent.originIp ? (
                        <>
                          {" · "}
                          <span title="The public address this agent calls from">
                            {agent.originIp}
                          </span>
                        </>
                      ) : null}
                    </p>

                    {agent.revoked && agent.revocationReason ? (
                      <p className="mt-1 text-[12px] text-[var(--block)]">
                        {agent.revocationReason}
                      </p>
                    ) : null}
                  </div>

                  <div className="shrink-0 text-right">
                    <div className="text-[10.5px] uppercase tracking-[0.06em] text-[var(--text-faint)]">
                      Trust
                    </div>
                    <div
                      className="text-[22px] font-semibold leading-none tnum"
                      style={{ color: trustColor }}
                    >
                      <Counter value={agent.trustScore} />
                    </div>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  {agent.capabilities.map((capability) => (
                    <span
                      key={capability}
                      className="mono rounded-[var(--r-sm)] border border-[var(--border)] bg-[var(--bg-inset)] px-1.5 py-[2px] text-[10.5px] text-[var(--text-muted)]"
                    >
                      {capability}
                    </span>
                  ))}
                  {agent.intel ? (
                    <IntelChip live={agent.intel.live} labels={agent.intel.labels} />
                  ) : null}
                </div>

                {agent.recent.length > 0 ? (
                  <div className="mt-3.5">
                    <div className="mb-1.5 text-[10px] uppercase tracking-[0.06em] text-[var(--text-faint)]">
                      Recent verdicts (newest first)
                    </div>
                    <div
                      className="flex flex-wrap items-end gap-[3px]"
                      role="img"
                      aria-label={`Last ${agent.recent.length} verdicts: ${agent.blocked} blocked, ${agent.flagged} flagged, the rest allowed.`}
                    >
                      {agent.recent.map((entry, index) => (
                        <span
                          key={index}
                          title={`${
                            entry.verdict === "ALLOW"
                              ? "Allowed"
                              : entry.verdict === "FLAG"
                                ? "Flagged"
                                : "Blocked"
                          } — risk score ${entry.score.toFixed(0)}`}
                          className="w-[6px] rounded-[2px] transition-[height,opacity] duration-[var(--d)] hover:opacity-70"
                          style={{
                            height: `${Math.max(5, Math.min(24, entry.score / 4.5 + 5))}px`,
                            background: VERDICT_COLOR[entry.verdict],
                          }}
                        />
                      ))}
                    </div>
                  </div>
                ) : null}

                <dl className="mt-3.5 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-[var(--text-faint)]">
                  <div className="flex gap-1.5">
                    <dt>Calls (1h)</dt>
                    <dd className="tnum text-[var(--text-muted)]">{agent.calls}</dd>
                  </div>
                  <div className="flex gap-1.5">
                    <dt>Blocked</dt>
                    <dd className="tnum text-[var(--text-muted)]">{agent.blocked}</dd>
                  </div>
                  <div className="flex gap-1.5">
                    <dt>Flagged</dt>
                    <dd className="tnum text-[var(--text-muted)]">{agent.flagged}</dd>
                  </div>
                  <div className="flex gap-1.5">
                    <dt>Enrolled</dt>
                    <dd className="text-[var(--text-muted)]">
                      {relativeTime(agent.registeredAt, now)}
                    </dd>
                  </div>
                  <div className="flex gap-1.5">
                    <dt>Key rotated</dt>
                    <dd className="text-[var(--text-muted)]">
                      {relativeTime(agent.keyRotatedAt, now)}
                    </dd>
                  </div>
                </dl>

                {agent.intel ? (
                  <>
                    <button
                      type="button"
                      onClick={() => setExpanded(open ? null : agent.agentId)}
                      aria-expanded={open}
                      className="tap mt-3 inline-flex items-center gap-1.5 rounded-[var(--r-sm)] text-[11.5px] font-medium text-[var(--accent)] transition-opacity hover:opacity-80"
                    >
                      {open ? "Hide external intel" : "Show external intel"}
                      <span
                        aria-hidden="true"
                        style={{
                          display: "inline-block",
                          transform: open ? "rotate(90deg)" : "none",
                          transition: "transform var(--d) var(--e-out)",
                        }}
                      >
                        ›
                      </span>
                    </button>

                    <div
                      className="grid"
                      style={{
                        gridTemplateRows: open ? "1fr" : "0fr",
                        transition: "grid-template-rows var(--d-slow) var(--e-out)",
                      }}
                    >
                      <div className="overflow-hidden">
                        <ul className="mt-2.5 space-y-1.5 rounded-[var(--r)] border border-[var(--border)] bg-[var(--bg-inset)] px-3 py-2.5">
                          {agent.intel.providers.map((provider) => (
                            <li key={provider.provider} className="text-[11.5px] leading-relaxed">
                              <span className="font-medium">{provider.provider}</span>
                              <span className="text-[var(--text-muted)]">
                                {" — "}
                                {provider.evidence}
                              </span>
                              {provider.reference ? (
                                <>
                                  {" "}
                                  <a
                                    href={provider.reference}
                                    target="_blank"
                                    rel="noreferrer noopener"
                                    className="text-[var(--accent)] underline underline-offset-2"
                                  >
                                    check
                                  </a>
                                </>
                              ) : null}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </>
                ) : null}

                <p className="mono mt-2.5 break-all text-[10px] text-[var(--text-faint)]">
                  capability root {agent.capabilityRoot.slice(0, 40)}…
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
