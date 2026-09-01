"use client";

import Link from "next/link";
import { useEffect } from "react";

/**
 * Route-level error boundary.
 *
 * A transient failure — a cold instance, a timed-out render — used to surface
 * as a blank page with nothing to act on. That is the worst possible failure
 * mode for a security product: the user cannot tell "the check said no" from
 * "the check never ran". This states which one happened and offers a retry.
 *
 * The digest is shown because it is the only identifier that ties what the user
 * saw to a server-side log line; the underlying error text is never rendered,
 * matching `fail()`'s opaque-error contract on the API side.
 */
export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[atf] route error", error.digest ?? error.message);
  }, [error]);

  return (
    <main className="mx-auto flex min-h-[60vh] max-w-[560px] flex-col items-center justify-center px-4 text-center">
      <div
        aria-hidden="true"
        className="mb-4 h-9 w-9 rounded-full border"
        style={{ borderColor: "var(--block-line)", background: "var(--block-soft)" }}
      />
      <h1 className="text-[18px] font-semibold tracking-[-0.02em]">
        This page didn&rsquo;t load
      </h1>
      <p className="mt-2 text-[13.5px] leading-relaxed text-[var(--text-muted)]">
        Something failed on the way here — most often a cold server instance that
        took too long to answer. Nothing was blocked or allowed as a result of
        this; the firewall itself is unaffected.
      </p>

      <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
        <button
          type="button"
          onClick={reset}
          className="tap rounded-[var(--r)] bg-[var(--accent)] px-3.5 py-2 text-[13px] font-medium text-[var(--accent-text)] transition-opacity hover:opacity-90"
        >
          Try again
        </button>
        <Link
          href="/"
          prefetch={false}
          className="tap rounded-[var(--r)] border border-[var(--border-strong)] bg-[var(--bg-raised)] px-3.5 py-2 text-[13px] font-medium transition-colors hover:bg-[var(--bg-hover)]"
        >
          Back to overview
        </Link>
      </div>

      {error.digest ? (
        <p className="mono mt-5 text-[11px] text-[var(--text-faint)]">
          reference {error.digest}
        </p>
      ) : null}
    </main>
  );
}
