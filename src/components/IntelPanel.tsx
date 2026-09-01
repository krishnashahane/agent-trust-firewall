"use client";

import type { IpIntel } from "@/lib/atf/types";

/**
 * External intelligence, shown provider by provider.
 *
 * The point of this panel is to *show the work*. Blending a third-party
 * reputation score silently into a number would be indistinguishable from
 * inventing one, so each provider gets its own row stating what it said, when,
 * whether the answer was live or cached, and a link to check the claim
 * independently.
 *
 * Providers that could not answer are listed too rather than hidden. An outage
 * is information — it tells the reader this verdict was reached with less
 * evidence than usual, which is exactly what a security operator needs to know.
 */

const ORIGIN_STYLE: Record<
  IpIntel["providers"][number]["origin"],
  { label: string; fg: string; bg: string; line: string }
> = {
  live: {
    label: "found",
    fg: "var(--block)",
    bg: "var(--block-soft)",
    line: "var(--block-line)",
  },
  "live-clean": {
    label: "clean",
    fg: "var(--allow)",
    bg: "var(--allow-soft)",
    line: "var(--allow-line)",
  },
  unavailable: {
    label: "no answer",
    fg: "var(--text-faint)",
    bg: "var(--bg-sunken)",
    line: "var(--border)",
  },
};

export function IntelPanel({ intel }: { intel: IpIntel }) {
  const answered = intel.providers.filter((p) => p.origin !== "unavailable").length;

  return (
    <section className="overflow-hidden rounded-[var(--r)] border border-[var(--border)]">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] bg-[var(--bg-inset)] px-3.5 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span
            aria-hidden="true"
            className={intel.live ? "live-dot h-1.5 w-1.5 rounded-full" : "h-1.5 w-1.5 rounded-full"}
            style={{
              background: intel.live ? "var(--accent)" : "var(--text-faint)",
            }}
          />
          <h4 className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-muted)]">
            External intelligence
          </h4>
          <span className="mono truncate text-[11px] text-[var(--text-faint)]">
            {intel.ip}
          </span>
        </div>
        <span className="text-[11px] text-[var(--text-faint)]">
          {intel.live
            ? `${answered} of ${intel.providers.length} providers answered`
            : "no provider answered"}
        </span>
      </header>

      {!intel.live ? (
        <p className="px-3.5 py-3 text-[12px] leading-relaxed text-[var(--text-muted)]">
          No external lookup succeeded for this origin, so this verdict used the
          firewall&rsquo;s own signals only. That is a smaller evidence base than
          usual, not a clean bill of health.
        </p>
      ) : null}

      <ul className="divide-y divide-[var(--border)]">
        {intel.providers.map((provider) => {
          const style = ORIGIN_STYLE[provider.origin];
          return (
            <li key={provider.provider} className="px-3.5 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[12px] font-medium">{provider.provider}</span>
                <span
                  className="rounded-full border px-1.5 py-[1px] text-[10px] font-medium"
                  style={{
                    color: style.fg,
                    background: style.bg,
                    borderColor: style.line,
                  }}
                >
                  {style.label}
                </span>
                {provider.cached ? (
                  <span
                    className="text-[10px] text-[var(--text-faint)]"
                    title="Served from this deployment's cache to stay inside provider rate limits."
                  >
                    cached
                  </span>
                ) : provider.ms > 0 ? (
                  <span className="mono text-[10px] text-[var(--text-faint)]">
                    {provider.ms}ms
                  </span>
                ) : null}
                {provider.reference ? (
                  <a
                    href={provider.reference}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="ml-auto text-[11px] text-[var(--accent)] underline underline-offset-2"
                  >
                    check it
                  </a>
                ) : null}
              </div>
              <p className="mt-1 text-[12px] leading-relaxed text-[var(--text-muted)]">
                {provider.evidence}
              </p>
            </li>
          );
        })}
      </ul>

      <footer className="border-t border-[var(--border)] bg-[var(--bg-inset)] px-3.5 py-2">
        <p className="text-[11px] leading-relaxed text-[var(--text-faint)]">
          Fetched server-side and cached. The agent is synthetic; the address and
          everything said about it here are real.
        </p>
      </footer>
    </section>
  );
}
