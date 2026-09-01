/**
 * Shared presentation primitives.
 *
 * Two rules hold everything here together:
 *
 *  1. **Colour never carries meaning alone.** Every verdict shows its word
 *     alongside its colour, so the UI still works for a colour-blind operator
 *     and in a printout.
 *  2. **Every async surface has a skeleton shaped like its result.** A bare
 *     "Loading…" string causes a layout jump and tells the reader nothing; a
 *     skeleton that matches the final layout does neither.
 */
import type { CSSProperties, ReactNode } from "react";
import type { RiskBand, Verdict } from "@/lib/atf/types";

/* -------------------------------------------------------------- verdicts -- */

const VERDICT: Record<
  Verdict,
  { fg: string; bg: string; line: string; label: string }
> = {
  ALLOW: {
    fg: "var(--allow)",
    bg: "var(--allow-soft)",
    line: "var(--allow-line)",
    label: "Allowed",
  },
  FLAG: {
    fg: "var(--flag)",
    bg: "var(--flag-soft)",
    line: "var(--flag-line)",
    label: "Flagged",
  },
  BLOCK: {
    fg: "var(--block)",
    bg: "var(--block-soft)",
    line: "var(--block-line)",
    label: "Blocked",
  },
};

export function VerdictBadge({
  verdict,
  size = "md",
  animate = false,
}: {
  verdict: Verdict;
  size?: "sm" | "md";
  /** play the landing animation — a block snaps, an allow settles */
  animate?: boolean;
}) {
  const v = VERDICT[verdict];
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border font-medium ${
        size === "sm" ? "px-2 py-[3px] text-[11.5px]" : "px-2.5 py-1 text-[12px]"
      } ${animate ? (verdict === "BLOCK" ? "verdict-block" : "verdict-settle") : ""}`}
      style={{ background: v.bg, color: v.fg, borderColor: v.line }}
    >
      <span
        aria-hidden="true"
        className="h-[5px] w-[5px] rounded-full"
        style={{ background: v.fg }}
      />
      {v.label}
    </span>
  );
}

const BAND_LABEL: Record<RiskBand, string> = {
  minimal: "Minimal risk",
  low: "Low risk",
  elevated: "Elevated risk",
  high: "High risk",
  critical: "Critical risk",
};

export function bandColor(band: RiskBand): string {
  if (band === "minimal" || band === "low") return "var(--allow)";
  if (band === "elevated") return "var(--flag)";
  return "var(--block)";
}

export function BandLabel({ band }: { band: RiskBand }) {
  return (
    <span className="text-[11.5px] font-medium" style={{ color: bandColor(band) }}>
      {BAND_LABEL[band]}
    </span>
  );
}

/** A score bar that fills rather than appearing at its final width. */
export function ScoreMeter({
  score,
  band,
  width = 72,
  fill = true,
  showValue = true,
}: {
  score: number;
  band: RiskBand;
  width?: number;
  /** false renders instantly — used inside virtualised/long lists */
  fill?: boolean;
  showValue?: boolean;
}) {
  const color = bandColor(band);
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-1 overflow-hidden rounded-full bg-[var(--bg-sunken)]"
        style={{ width }}
        role="img"
        aria-label={`Risk score ${score.toFixed(0)} of 100 — ${BAND_LABEL[band]}`}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${Math.max(2, Math.min(100, score))}%`,
            background: color,
            transition: fill
              ? "width var(--d-slow) var(--e-out), background var(--d) linear"
              : "none",
          }}
        />
      </div>
      {showValue ? (
        <span className="mono tnum text-[11.5px]" style={{ color }}>
          {score.toFixed(0)}
        </span>
      ) : null}
    </div>
  );
}

/* ---------------------------------------------------------------- panels -- */

export function Panel({
  title,
  caption,
  action,
  children,
  className = "",
  as: Tag = "section",
}: {
  title?: string;
  /** one line telling a first-time reader what they are looking at */
  caption?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  as?: "section" | "div";
}) {
  return (
    <Tag className={`panel overflow-hidden ${className}`}>
      {title ? (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-[var(--border)] px-4 py-3 sm:px-5">
          <div className="min-w-0">
            <h2 className="text-[13.5px] font-semibold tracking-tight">{title}</h2>
            {caption ? (
              <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-[var(--text-muted)]">
                {caption}
              </p>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </header>
      ) : null}
      {children}
    </Tag>
  );
}

export function Stat({
  label,
  value,
  tone = "default",
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "allow" | "flag" | "block" | "seal";
  hint?: string;
}) {
  const color =
    tone === "allow"
      ? "var(--allow)"
      : tone === "flag"
        ? "var(--flag)"
        : tone === "block"
          ? "var(--block)"
          : tone === "seal"
            ? "var(--seal)"
            : "var(--text)";
  return (
    <div className="panel stat-tile px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-faint)]">
        {label}
      </div>
      <div
        className="mt-1.5 text-[26px] font-semibold leading-none tracking-tight tnum"
        style={{ color }}
      >
        {value}
      </div>
      {hint ? (
        <div className="mt-1.5 text-[11.5px] text-[var(--text-muted)]">{hint}</div>
      ) : null}
    </div>
  );
}

/* --------------------------------------------------------------- states --- */

export function Skeleton({
  width,
  height = 12,
  className = "",
  style,
}: {
  width?: number | string;
  height?: number | string;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      aria-hidden="true"
      className={`skeleton ${className}`}
      style={{ width, height, ...style }}
    />
  );
}

/**
 * Wraps a loading region so assistive tech announces it as busy rather than as
 * a pile of empty boxes.
 */
export function LoadingRegion({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div role="status" aria-busy="true" aria-label={label}>
      <span className="sr-only">{label}</span>
      {children}
    </div>
  );
}

/** Empty states teach instead of showing a zero. */
export function EmptyState({
  title,
  body,
  action,
  tone = "neutral",
}: {
  title: string;
  body: string;
  action?: ReactNode;
  tone?: "neutral" | "error";
}) {
  return (
    <div className="px-5 py-10 text-center">
      <div
        aria-hidden="true"
        className="mx-auto mb-3 h-8 w-8 rounded-full border"
        style={{
          borderColor: tone === "error" ? "var(--block-line)" : "var(--border-strong)",
          background: tone === "error" ? "var(--block-soft)" : "var(--bg-sunken)",
        }}
      />
      <p className="text-[13.5px] font-medium">{title}</p>
      <p className="mx-auto mt-1.5 max-w-md text-[12.5px] leading-relaxed text-[var(--text-muted)]">
        {body}
      </p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

/* --------------------------------------------------------------- buttons -- */

export function Button({
  children,
  onClick,
  variant = "secondary",
  size = "md",
  disabled,
  type = "button",
  href,
  className = "",
  ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md";
  disabled?: boolean;
  type?: "button" | "submit";
  href?: string;
  className?: string;
  ariaLabel?: string;
}) {
  const base =
    "tap inline-flex items-center justify-center gap-2 rounded-[var(--r)] font-medium transition-[background,color,border-color,transform,opacity] duration-[var(--d-fast)] active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50";
  const sizing = size === "sm" ? "px-2.5 py-1.5 text-[12px]" : "px-3.5 py-2 text-[13px]";
  const look =
    variant === "primary"
      ? "bg-[var(--accent)] text-[var(--accent-text)] hover:bg-[var(--accent-hover)]"
      : variant === "secondary"
        ? "border border-[var(--border-strong)] bg-[var(--bg-raised)] text-[var(--text)] hover:bg-[var(--bg-hover)]"
        : "text-[var(--text-muted)] hover:bg-[var(--bg-hover)] hover:text-[var(--text)]";

  if (href) {
    return (
      <a href={href} className={`${base} ${sizing} ${look} ${className}`} aria-label={ariaLabel}>
        {children}
      </a>
    );
  }
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className={`${base} ${sizing} ${look} ${className}`}
    >
      {children}
    </button>
  );
}

/* ----------------------------------------------------------------- intel -- */

/**
 * The provenance chip.
 *
 * This is a small component carrying a large promise: it states, on the row it
 * annotates, whether a number came from a live third-party lookup or from the
 * engine's own synthetic view. Presenting external intel without this
 * distinction would be the dishonest version of the feature.
 */
export function IntelChip({
  live,
  labels,
  className = "",
}: {
  live: boolean;
  labels: string[];
  className?: string;
}) {
  if (!live) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] bg-[var(--bg-inset)] px-2 py-[3px] text-[11px] text-[var(--text-faint)] ${className}`}
        title="No live third-party lookup was available; the verdict used the engine's own signals only."
      >
        <span aria-hidden="true" className="h-[5px] w-[5px] rounded-full bg-[var(--text-faint)]" />
        synthetic only
      </span>
    );
  }

  const hostile = labels.length > 0;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-[3px] text-[11px] font-medium ${className}`}
      style={{
        background: hostile ? "var(--block-soft)" : "var(--allow-soft)",
        color: hostile ? "var(--block)" : "var(--allow)",
        borderColor: hostile ? "var(--block-line)" : "var(--allow-line)",
      }}
      title={
        hostile
          ? `Live threat intelligence: ${labels.join(", ")}`
          : "Live threat intelligence found nothing on this origin."
      }
    >
      <span
        aria-hidden="true"
        className="live-dot h-[5px] w-[5px] rounded-full"
        style={{ background: hostile ? "var(--block)" : "var(--allow)" }}
      />
      {hostile ? `live intel · ${labels.slice(0, 2).join(", ")}` : "live intel · clean"}
    </span>
  );
}

/* ------------------------------------------------------------------ misc -- */

export function relativeTime(timestamp: number, now: number): string {
  const seconds = Math.max(0, Math.round((now - timestamp) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}
