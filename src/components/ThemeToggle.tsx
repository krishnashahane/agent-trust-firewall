"use client";

import { useCallback, useSyncExternalStore } from "react";

type Theme = "light" | "dark";

/**
 * Theme switch.
 *
 * Light is the product's default and the only state the CSS defines on bare
 * `:root`. The OS `prefers-color-scheme` setting is deliberately *not*
 * consulted: a visitor whose machine is dark still gets the light console
 * unless they choose otherwise here, so what everyone sees first is the same
 * thing. Dark is a stored, explicit choice.
 *
 * Read through `useSyncExternalStore` because the value lives in localStorage —
 * an external store — rather than in React state. Doing it in an effect would
 * cost an extra render on every mount and flag a state update inside the effect
 * commit.
 */

const STORAGE_KEY = "atf-theme";

function getSnapshot(): Theme {
  try {
    return localStorage.getItem(STORAGE_KEY) === "dark" ? "dark" : "light";
  } catch {
    // A browser blocking site data is not an error — it just has no preference.
    return "light";
  }
}

/** The server has no localStorage, and light is what it renders. */
const getServerSnapshot = (): Theme => "light";

function subscribe(onChange: () => void): () => void {
  // `storage` covers another tab changing the choice; the custom event covers
  // this tab, since `storage` does not fire for the writer.
  window.addEventListener("storage", onChange);
  window.addEventListener("atf-theme-change", onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener("atf-theme-change", onChange);
  };
}

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    const root = document.documentElement;
    if (next === "dark") root.setAttribute("data-theme", "dark");
    else root.removeAttribute("data-theme");

    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Blocked storage must not break the toggle for this page view.
    }
    window.dispatchEvent(new Event("atf-theme-change"));
  }, [theme]);

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={
        theme === "dark" ? "Switch to light theme" : "Switch to dark theme"
      }
      aria-pressed={theme === "dark"}
      className="tap flex h-9 w-9 items-center justify-center rounded-[var(--r)] border border-[var(--border)] bg-[var(--bg-inset)] text-[var(--text-muted)] transition-colors duration-[var(--d-fast)] hover:text-[var(--text)]"
    >
      <span
        className="grid place-items-center"
        style={{
          transform: theme === "dark" ? "rotate(-90deg)" : "none",
          transition: "transform var(--d-slow) var(--e-out)",
        }}
      >
        {theme === "dark" ? <Sun /> : <Moon />}
      </span>
    </button>
  );
}

function Sun() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="M12 2.8v2.1M12 19.1v2.1M2.8 12h2.1M19.1 12h2.1M5.5 5.5l1.5 1.5M17 17l1.5 1.5M18.5 5.5 17 7M7 17l-1.5 1.5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
}

function Moon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M20 14.2A8.2 8.2 0 0 1 9.8 4a8.2 8.2 0 1 0 10.2 10.2Z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
    </svg>
  );
}
