"use client";

/**
 * Site navigation.
 *
 * Seven destinations do not fit on a 375px screen, and the previous version
 * simply let them overflow — which silently made most of the product
 * unreachable on a phone. Below `md` the links move into a drawer.
 *
 * The drawer is built to the usual dialog contract rather than as a styled
 * div: focus moves into it on open and returns to the trigger on close, Tab is
 * trapped inside it, Escape dismisses it, background scroll is locked, and the
 * trigger carries aria-expanded/aria-controls. A nav that a keyboard or screen
 * reader user cannot escape is worse than one that overflows.
 */

import { usePathname } from "next/navigation";
import Link from "next/link";
import { useCallback, useEffect, useId, useRef, useState } from "react";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/console", label: "Console" },
  { href: "/console/agents", label: "Agents" },
  { href: "/console/attack-range", label: "Attack range" },
  { href: "/console/audit", label: "Audit" },
  { href: "/console/tuning", label: "Tuning" },
  { href: "/glossary", label: "Glossary" },
] as const;

function useIsActive() {
  const pathname = usePathname();
  return useCallback(
    (href: string) => (href === "/" ? pathname === "/" : pathname === href),
    [pathname],
  );
}

export function Nav() {
  const isActive = useIsActive();
  const pathname = usePathname();
  const listRef = useRef<HTMLUListElement | null>(null);
  const [marker, setMarker] = useState<{ left: number; width: number } | null>(null);
  // The first placement must not animate: sliding in from the left edge on
  // page load reads as a glitch, and a late re-measure once webfonts settle
  // would otherwise replay the whole transition seconds after arrival.
  const placed = useRef(false);

  // Measure the active link and move a single underline to it, so navigating
  // slides the indicator instead of extinguishing one and lighting another.
  // Measured rather than hard-coded because the labels have different widths
  // and the font may not have settled on first paint.
  useEffect(() => {
    const measure = () => {
      const list = listRef.current;
      const active = list?.querySelector<HTMLElement>('[aria-current="page"]');
      if (!list || !active) {
        setMarker(null);
        return;
      }
      setMarker({ left: active.offsetLeft, width: active.offsetWidth });
    };

    // Deferred a frame: on first paint the font may still be swapping, which
    // would measure a width the label no longer has.
    const raf = requestAnimationFrame(measure);
    window.addEventListener("resize", measure);
    // Re-measure once webfonts settle, but without animating — the label
    // widths only shift by a pixel or two and animating that looks like a
    // fault rather than a transition.
    document.fonts?.ready
      .then(() => {
        placed.current = false;
        measure();
      })
      .catch(() => {});
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", measure);
    };
  }, [pathname]);

  return (
    <nav aria-label="Primary" className="relative hidden min-w-0 flex-1 md:block">
      <ul ref={listRef} className="relative flex items-center gap-0.5">
        {LINKS.map((link) => {
          const active = isActive(link.href);
          return (
            <li key={link.href}>
              <Link
                href={link.href}
                // Prefetch is off deliberately. Every route here renders
                // dynamically (the CSP nonce requires a per-request render), so
                // Next's default viewport prefetch fired seven function
                // invocations on *every* page view — enough to starve a cold
                // instance and return 503s on the very navigation it was meant
                // to speed up. Same-origin navigation is already fast.
                prefetch={false}
                aria-current={active ? "page" : undefined}
                className={`relative block rounded-[var(--r-sm)] px-2.5 py-1.5 text-[13px] transition-colors duration-[var(--d-fast)] ${
                  active
                    ? "font-medium text-[var(--text)]"
                    : "text-[var(--text-muted)] hover:bg-[var(--bg-hover)] hover:text-[var(--text)]"
                }`}
              >
                {link.label}
              </Link>
            </li>
          );
        })}

        {/* One shared indicator. A rule under the label rather than a filled
          * pill: less chrome, and it reads as "you are here" without competing
          * with the accent reserved for actions. */}
        {marker ? (
          <span
            aria-hidden="true"
            className="absolute -bottom-[13px] h-[2px] rounded-full bg-[var(--accent)]"
            ref={(node) => {
              if (!node) return;
              // Animate only once a position is already established, so the
              // indicator glides between destinations but never slides in from
              // nowhere on the first paint.
              const shouldAnimate = placed.current;
              node.style.transition = shouldAnimate
                ? "left var(--d-slow) var(--e-out), width var(--d-slow) var(--e-out)"
                : "none";
              placed.current = true;
            }}
            style={{
              left: marker.left + 10,
              width: Math.max(0, marker.width - 20),
            }}
          />
        ) : null}
      </ul>
    </nav>
  );
}

export function MobileNav() {
  const isActive = useIsActive();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);

  // Note: the drawer closes from each link's own onClick rather than from an
  // effect watching the pathname. Same result, but the close is caused by the
  // interaction that triggered it instead of by a state write during render.

  useEffect(() => {
    if (!open) return;

    const { overflow } = document.body.style;
    document.body.style.overflow = "hidden";

    // Move focus into the drawer so the next Tab lands inside it.
    const focusFirst = window.setTimeout(() => {
      panelRef.current?.querySelector<HTMLElement>("a, button")?.focus();
    }, 20);

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
        return;
      }
      if (event.key !== "Tab") return;

      const focusables = panelRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled])',
      );
      if (!focusables || focusables.length === 0) return;

      const first = focusables[0] as HTMLElement;
      const last = focusables[focusables.length - 1] as HTMLElement;
      // Wrap at both ends so focus cannot escape behind the overlay.
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    const trigger = triggerRef.current;
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = overflow;
      window.clearTimeout(focusFirst);
      // Focus returns to the control that opened the drawer, not to whatever
      // happened to be focused beforehand — otherwise closing can strand focus
      // on <body> and a keyboard user restarts their tab journey from the top.
      trigger?.focus();
    };
  }, [open]);

  return (
    <div className="md:hidden">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={open ? "Close navigation menu" : "Open navigation menu"}
        className="tap flex h-9 w-9 items-center justify-center rounded-[var(--r)] border border-[var(--border)] bg-[var(--bg-inset)] text-[var(--text-muted)] transition-colors hover:text-[var(--text)]"
      >
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
          {/* The two bars rotate into a cross rather than swapping icons, so
           * the control reads as one object changing state. */}
          <line
            x1="2"
            y1="5"
            x2="14"
            y2="5"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            style={{
              transformOrigin: "center",
              transform: open ? "translateY(3px) rotate(45deg)" : "none",
              transition: "transform var(--d) var(--e-out)",
            }}
          />
          <line
            x1="2"
            y1="11"
            x2="14"
            y2="11"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            style={{
              transformOrigin: "center",
              transform: open ? "translateY(-3px) rotate(-45deg)" : "none",
              transition: "transform var(--d) var(--e-out)",
            }}
          />
        </svg>
      </button>

      {/* Overlay + panel stay mounted so they can animate out; `hidden` keeps
       * them out of the accessibility tree and tab order when closed. */}
      <div
        hidden={!open}
        className="fixed inset-0 z-50"
        // The overlay is a backdrop, not a control; the close affordances are
        // the trigger, Escape, and the links themselves.
        aria-hidden="true"
        onClick={() => setOpen(false)}
        style={{
          background: "rgb(0 0 0 / 0.32)",
          opacity: open ? 1 : 0,
          transition: "opacity var(--d) var(--e-out)",
        }}
      />

      <div
        ref={panelRef}
        id={panelId}
        role="dialog"
        aria-modal="true"
        aria-label="Site navigation"
        hidden={!open}
        className="fixed inset-x-0 top-[57px] z-50 border-b border-[var(--border)] bg-[var(--bg-raised)] px-3 pb-3 pt-2 shadow-[var(--shadow)]"
        style={{
          transform: open ? "none" : "translate3d(0, -8px, 0)",
          opacity: open ? 1 : 0,
          transition:
            "transform var(--d) var(--e-out), opacity var(--d) var(--e-out)",
        }}
      >
        <ul className="flex flex-col">
          {LINKS.map((link) => {
            const active = isActive(link.href);
            return (
              <li key={link.href}>
                <Link
                  href={link.href}
                  prefetch={false}
                  aria-current={active ? "page" : undefined}
                  onClick={() => setOpen(false)}
                  className={`flex min-h-[44px] items-center justify-between rounded-[var(--r)] px-3 text-[14px] transition-colors ${
                    active
                      ? "bg-[var(--accent-soft)] font-medium text-[var(--accent)]"
                      : "text-[var(--text-muted)] hover:bg-[var(--bg-hover)] hover:text-[var(--text)]"
                  }`}
                >
                  {link.label}
                  {active ? (
                    <span
                      aria-hidden="true"
                      className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]"
                    />
                  ) : null}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
