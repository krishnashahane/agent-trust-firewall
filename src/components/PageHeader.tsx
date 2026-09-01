import type { ReactNode } from "react";

/**
 * The header every console page opens with.
 *
 * The lede is not decoration — each console page drops the reader into a dense
 * technical surface, and one plain sentence explaining what they are looking at
 * is the difference between a dashboard and a wall of numbers.
 */
export function PageHeader({
  title,
  lede,
  action,
}: {
  title: string;
  lede: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold tracking-[-0.02em]">{title}</h1>
        <p className="mt-1.5 max-w-2xl text-[13.5px] leading-relaxed text-[var(--text-muted)]">
          {lede}
        </p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}
