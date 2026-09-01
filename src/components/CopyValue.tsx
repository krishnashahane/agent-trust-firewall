"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * A click-to-copy cryptographic value.
 *
 * This product asks people to check things for themselves — compare a digest,
 * look an address up with a provider, confirm a chain link. Every one of those
 * starts with selecting a truncated monospace string out of a dense table,
 * which is exactly the kind of small friction that stops people verifying at
 * all. One click copies the *full* value even though the display is truncated.
 *
 * It is a button, not a div with an onClick: keyboard users get it for free,
 * and the copied state is announced rather than only shown.
 */
export function CopyValue({
  value,
  display,
  className = "",
  title,
}: {
  /** the complete value placed on the clipboard */
  value: string;
  /** what is rendered; defaults to the value itself */
  display?: string;
  className?: string;
  title?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard access can be refused (permissions, insecure context, an
      // embedded webview). Selecting the text by hand still works, so this
      // stays silent rather than throwing an error at someone mid-task.
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={() => void copy()}
      title={title ?? `Copy ${value}`}
      aria-label={`Copy ${title ?? "value"} to clipboard`}
      className={`copyable mono inline-flex items-center gap-1 text-left ${className}`}
    >
      <span className="truncate">{display ?? value}</span>
      <span
        aria-hidden="true"
        className="shrink-0"
        style={{
          // The tick replaces the icon in place rather than appearing beside
          // it, so the row's width never changes and the table cannot reflow
          // under the cursor.
          opacity: copied ? 1 : 0.45,
          color: copied ? "var(--allow)" : "inherit",
          transition: "opacity var(--d-fast) var(--e-out), color var(--d-fast) linear",
        }}
      >
        {copied ? <TickIcon /> : <CopyIcon />}
      </span>
      <span className="sr-only" role="status">
        {copied ? "Copied to clipboard" : ""}
      </span>
    </button>
  );
}

function CopyIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.6" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M10.5 3.2A1.7 1.7 0 0 0 8.8 2H3.7A1.7 1.7 0 0 0 2 3.7v5.1a1.7 1.7 0 0 0 1.2 1.6"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function TickIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M3 8.6l3.2 3.2L13 5"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
