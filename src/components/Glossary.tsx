"use client";

import { useMemo, useState } from "react";
import { Reveal } from "@/components/motion";

export interface Term {
  term: string;
  plain: string;
  detail: string;
}

const slug = (term: string) =>
  term
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

/**
 * Reference content, kept dense and scannable.
 *
 * The list is long enough that pure linear scroll is a reachability problem, so
 * it gets a filter and per-term anchors. Motion is deliberately restrained here
 * — a light stagger on first paint and nothing else. Animating a reference list
 * per card would make it harder to use, not better.
 */
export function Glossary({ terms }: { terms: Term[] }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return terms;
    return terms.filter(
      (t) =>
        t.term.toLowerCase().includes(q) ||
        t.plain.toLowerCase().includes(q) ||
        t.detail.toLowerCase().includes(q),
    );
  }, [query, terms]);

  return (
    <>
      <div className="mb-5">
        <label htmlFor="glossary-filter" className="sr-only">
          Filter glossary terms
        </label>
        <input
          id="glossary-filter"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter terms…"
          className="w-full rounded-[var(--r)] border border-[var(--border)] bg-[var(--bg-raised)] px-3 py-2.5 text-[13px] text-[var(--text)] placeholder:text-[var(--text-faint)] focus-visible:border-[var(--accent)]"
        />

        {!query ? (
          <nav aria-label="Jump to term" className="mt-3 flex flex-wrap gap-1.5">
            {terms.map((t) => (
              <a
                key={t.term}
                href={`#${slug(t.term)}`}
                className="rounded-full border border-[var(--border)] bg-[var(--bg-raised)] px-2 py-[3px] text-[11px] text-[var(--text-muted)] transition-colors duration-[var(--d-fast)] hover:border-[var(--border-strong)] hover:text-[var(--text)]"
              >
                {t.term}
              </a>
            ))}
          </nav>
        ) : (
          <p className="mt-2.5 text-[12px] text-[var(--text-muted)]" role="status">
            {filtered.length} of {terms.length} terms match &ldquo;{query}&rdquo;.
          </p>
        )}
      </div>

      {filtered.length === 0 ? (
        <p className="panel px-5 py-8 text-center text-[13px] text-[var(--text-muted)]">
          No term matches that. Every piece of jargon this product uses should be on
          this page — if something is missing, that is a documentation bug.
        </p>
      ) : (
        <dl className="space-y-2.5">
          {filtered.map((entry, index) => (
            <Reveal key={entry.term} delay={Math.min(index, 8) * 30}>
              <div
                id={slug(entry.term)}
                className="panel scroll-mt-20 px-4 py-4 sm:px-5"
              >
                <dt className="text-[13.5px] font-semibold">{entry.term}</dt>
                <dd className="mt-1 text-[13px] font-medium text-[var(--accent)]">
                  {entry.plain}
                </dd>
                <dd className="mt-1.5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                  {entry.detail}
                </dd>
              </div>
            </Reveal>
          ))}
        </dl>
      )}
    </>
  );
}
