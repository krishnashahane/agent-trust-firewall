"use client";

import { useCallback, useEffect, useState } from "react";
import { Button, LoadingRegion, Panel, Skeleton } from "@/components/ui";
import { Counter, useDebounced } from "@/components/motion";
import type { RiskConfig } from "@/lib/atf/risk/config";

interface Preview {
  sampled: number;
  allowed: number;
  flagged: number;
  blocked: number;
  changed: number;
}

const WEIGHT_LABELS: Record<keyof RiskConfig["weights"], string> = {
  identity: "Identity posture",
  context: "Request context",
  behavior: "Behaviour baseline",
  rate: "Request rate",
  payload: "Payload inspection",
  reputation: "Recent reputation",
  intel: "External intel",
};

const WEIGHT_HINTS: Record<keyof RiskConfig["weights"], string> = {
  identity: "Key age, rotation, revocation",
  context: "Capability fit and blast radius",
  behavior: "Deviation from this agent's own baseline",
  rate: "Sustained volume and sudden bursts",
  payload: "Injection patterns and credential shapes",
  reputation: "This agent's recent verdicts",
  intel: "Live third-party lookups on the origin address",
};

const ORDER = Object.keys(WEIGHT_LABELS) as (keyof RiskConfig["weights"])[];

/**
 * The risk tuner.
 *
 * It exists to prove the engine is real: move a weight and the numbers move
 * with it, recomputed server-side over traffic that actually happened.
 *
 * Two changes over the first version. The recompute is debounced, so dragging a
 * slider fires one request when you pause rather than one per pixel — that was
 * both a latency problem and a needless load on the engine. And the result
 * panel now has a skeleton in the shape of its three bars, so it no longer
 * flashes a bare "Computing…" and shifts the layout underneath the cursor.
 */
export function RiskTuner() {
  const [config, setConfig] = useState<RiskConfig | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [saved, setSaved] = useState(false);
  const [sandboxed, setSandboxed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // One recompute when the drag settles, not one per pointer move.
  const debouncedConfig = useDebounced(config, 280);

  useEffect(() => {
    const first = setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch("/api/config", { cache: "no-store" });
          if (!response.ok) throw new Error();
          const data = (await response.json()) as {
            config: RiskConfig;
            sandboxed: boolean;
          };
          setConfig(data.config);
          setSandboxed(data.sandboxed);
        } catch {
          setError("Could not load the current configuration.");
        }
      })();
    }, 0);
    return () => clearTimeout(first);
  }, []);

  const runPreview = useCallback(async (next: RiskConfig) => {
    setPreviewing(true);
    try {
      const response = await fetch("/api/config/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(next),
      });
      if (!response.ok) throw new Error();
      setPreview((await response.json()) as Preview);
      setError(null);
    } catch {
      setError("Preview failed — the proposed configuration was rejected.");
    } finally {
      setPreviewing(false);
    }
  }, []);

  useEffect(() => {
    if (!debouncedConfig) return;
    // Deferred a task: runPreview flips a loading flag synchronously, and doing
    // that inside the effect commit forces a cascading render.
    const timer = setTimeout(() => void runPreview(debouncedConfig), 0);
    return () => clearTimeout(timer);
  }, [debouncedConfig, runPreview]);

  const apply = async () => {
    if (!config) return;
    try {
      const response = await fetch("/api/config", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(config),
      });
      if (!response.ok) throw new Error();
      setSaved(true);
      setSandboxed(true);
      setTimeout(() => setSaved(false), 2400);
    } catch {
      setError("Could not apply the configuration.");
    }
  };

  const resetToDefaults = async () => {
    try {
      const response = await fetch("/api/config", { method: "DELETE" });
      if (!response.ok) throw new Error();
      const data = (await response.json()) as { config: RiskConfig };
      setConfig(data.config);
      setSandboxed(false);
    } catch {
      setError("Could not reset the configuration.");
    }
  };

  if (!config) {
    return (
      <div className="grid gap-4 lg:grid-cols-[1fr_320px] lg:items-start">
        <Panel title="Risk tuning" caption="Loading the live configuration.">
          <LoadingRegion label="Loading risk configuration">
            <div className="space-y-5 px-4 py-5 sm:px-5">
              {Array.from({ length: 7 }, (_, i) => (
                <div key={i} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Skeleton width={`${28 + ((i * 7) % 18)}%`} height={11} />
                    <Skeleton width={28} height={11} />
                  </div>
                  <Skeleton width="100%" height={4} />
                </div>
              ))}
            </div>
          </LoadingRegion>
        </Panel>
        <Panel title="Effect on recent traffic" caption="Waiting for the configuration.">
          <PreviewSkeleton />
        </Panel>
      </div>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_320px] lg:items-start">
      <Panel
        title="Risk tuning"
        caption="Change how much each signal counts and where the thresholds sit. The effect on recent traffic recomputes when you let go."
        action={
          <div className="flex items-center gap-1.5">
            {sandboxed ? (
              <Button variant="ghost" size="sm" onClick={() => void resetToDefaults()}>
                Reset
              </Button>
            ) : null}
            <Button variant="primary" size="sm" onClick={() => void apply()}>
              {saved ? "Applied ✓" : "Apply to my sandbox"}
            </Button>
          </div>
        }
      >
        <div className="space-y-5 px-4 py-5 sm:px-5">
          {/* Whose settings these are is load-bearing information, not a
            * nicety: applying used to change the engine for every concurrent
            * visitor, and a reader needs to know that is no longer true. */}
          <p
            className="rounded-[var(--r)] border px-3.5 py-2.5 text-[12px] leading-relaxed"
            style={{
              borderColor: sandboxed ? "var(--accent-line)" : "var(--border)",
              background: sandboxed ? "var(--accent-soft)" : "var(--bg-inset)",
              color: sandboxed ? "var(--accent)" : "var(--text-muted)",
            }}
          >
            {sandboxed ? (
              <>
                <b className="font-semibold">You are in a personal sandbox.</b> These
                settings apply to your session only and expire after an hour. Nobody
                else&rsquo;s view of the firewall is affected.
              </>
            ) : (
              <>
                You are viewing the shared defaults. Applying a change creates a
                private sandbox for your session — it never alters what other
                visitors see.
              </>
            )}
          </p>

          <fieldset>
            <legend className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
              Signal weights
            </legend>
            <div className="mt-3.5 space-y-4">
              {ORDER.map((key) => (
                <div key={key}>
                  <div className="flex items-baseline justify-between gap-3">
                    <label htmlFor={`weight-${key}`} className="text-[12.5px] font-medium">
                      {WEIGHT_LABELS[key]}
                    </label>
                    <span className="mono tnum text-[11.5px] text-[var(--text-muted)]">
                      {config.weights[key].toFixed(2)}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-[var(--text-faint)]">
                    {WEIGHT_HINTS[key]}
                  </p>
                  <input
                    id={`weight-${key}`}
                    type="range"
                    min={0}
                    max={1}
                    step={0.05}
                    value={config.weights[key]}
                    aria-valuetext={`${config.weights[key].toFixed(2)} of 1`}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        weights: { ...config.weights, [key]: Number(e.target.value) },
                      })
                    }
                    className="mt-2 h-6 w-full cursor-pointer accent-[var(--accent)]"
                  />
                </div>
              ))}
            </div>
          </fieldset>

          <fieldset className="border-t border-[var(--border)] pt-4">
            <legend className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
              Thresholds
            </legend>
            <div className="mt-3.5 space-y-4">
              <div>
                <div className="flex items-baseline justify-between gap-3">
                  <label htmlFor="threshold-flag" className="text-[12.5px] font-medium">
                    Flag for review at
                  </label>
                  <span className="mono tnum text-[11.5px]" style={{ color: "var(--flag)" }}>
                    {config.thresholds.flag}
                  </span>
                </div>
                <input
                  id="threshold-flag"
                  type="range"
                  min={0}
                  max={100}
                  step={1}
                  value={config.thresholds.flag}
                  aria-valuetext={`${config.thresholds.flag} of 100`}
                  onChange={(e) => {
                    const flag = Number(e.target.value);
                    setConfig({
                      ...config,
                      thresholds: {
                        flag,
                        // The schema rejects flag > block; keep them consistent
                        // while dragging rather than failing the preview.
                        block: Math.max(flag, config.thresholds.block),
                      },
                    });
                  }}
                  className="mt-2 h-6 w-full cursor-pointer accent-[var(--flag)]"
                />
              </div>

              <div>
                <div className="flex items-baseline justify-between gap-3">
                  <label htmlFor="threshold-block" className="text-[12.5px] font-medium">
                    Block at
                  </label>
                  <span className="mono tnum text-[11.5px]" style={{ color: "var(--block)" }}>
                    {config.thresholds.block}
                  </span>
                </div>
                <input
                  id="threshold-block"
                  type="range"
                  min={0}
                  max={100}
                  step={1}
                  value={config.thresholds.block}
                  aria-valuetext={`${config.thresholds.block} of 100`}
                  onChange={(e) => {
                    const block = Number(e.target.value);
                    setConfig({
                      ...config,
                      thresholds: {
                        block,
                        flag: Math.min(block, config.thresholds.flag),
                      },
                    });
                  }}
                  className="mt-2 h-6 w-full cursor-pointer accent-[var(--block)]"
                />
              </div>
            </div>
          </fieldset>

          <p className="border-t border-[var(--border)] pt-4 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
            These sliders move judgement calls only. A revoked key, an unverified
            proof, a replayed challenge or an ungranted capability is blocked at every
            setting on this page — those are not tunable, by design.
          </p>
        </div>
      </Panel>

      <Panel
        title="Effect on recent traffic"
        caption="Recomputed server-side over the last 200 recorded calls, without committing the change."
      >
        <div className="px-4 py-5 sm:px-5">
          {error ? (
            <p className="text-[12.5px] text-[var(--block)]">{error}</p>
          ) : previewing && !preview ? (
            <PreviewSkeleton bare />
          ) : !preview ? (
            <PreviewSkeleton bare />
          ) : (
            <div
              className="space-y-3.5"
              style={{
                opacity: previewing ? 0.55 : 1,
                transition: "opacity var(--d) var(--e-out)",
              }}
            >
              <p className="text-[12px] text-[var(--text-muted)]">
                Across <Counter value={preview.sampled} /> recorded call
                {preview.sampled === 1 ? "" : "s"}:
              </p>

              {(
                [
                  { label: "Allowed", value: preview.allowed, color: "var(--allow)" },
                  { label: "Flagged", value: preview.flagged, color: "var(--flag)" },
                  { label: "Blocked", value: preview.blocked, color: "var(--block)" },
                ] as const
              ).map((row) => (
                <div key={row.label}>
                  <div className="flex items-baseline justify-between text-[12px]">
                    <span>{row.label}</span>
                    <span className="mono tnum" style={{ color: row.color }}>
                      <Counter value={row.value} />
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-[var(--bg-sunken)]">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${
                          preview.sampled > 0 ? (row.value / preview.sampled) * 100 : 0
                        }%`,
                        background: row.color,
                        transition: "width var(--d-slow) var(--e-out)",
                      }}
                    />
                  </div>
                </div>
              ))}

              <p className="border-t border-[var(--border)] pt-3.5 text-[12px] text-[var(--text-muted)]">
                <span className="font-semibold text-[var(--text)]">
                  <Counter value={preview.changed} />
                </span>{" "}
                verdict{preview.changed === 1 ? "" : "s"} would change under this
                configuration.
              </p>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

/** Matches the three-bar result layout exactly, so nothing shifts on arrival. */
function PreviewSkeleton({ bare = false }: { bare?: boolean }) {
  const body = (
    <div className="space-y-3.5">
      <Skeleton width="58%" height={11} />
      {[0, 1, 2].map((i) => (
        <div key={i}>
          <div className="flex items-baseline justify-between">
            <Skeleton width={54} height={11} />
            <Skeleton width={20} height={11} />
          </div>
          <Skeleton width="100%" height={6} className="mt-1.5" />
        </div>
      ))}
      <div className="border-t border-[var(--border)] pt-3.5">
        <Skeleton width="72%" height={11} />
      </div>
    </div>
  );

  return (
    <LoadingRegion label="Recomputing the effect on recent traffic">
      {bare ? body : <div className="px-4 py-5 sm:px-5">{body}</div>}
    </LoadingRegion>
  );
}
