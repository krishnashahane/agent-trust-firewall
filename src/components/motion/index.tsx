"use client";

/**
 * The motion system.
 *
 * Four primitives cover every animation in the product: reveal-on-scroll,
 * tweened numbers, staggered sequences, and a reduced-motion hook the others
 * are built on. Durations and easings come from CSS tokens in globals.css, so
 * timing is tuned in one place rather than per component.
 *
 * Why no animation library: everything here is transform/opacity driven by CSS
 * transitions and one IntersectionObserver, which is a few hundred bytes and
 * stays on the compositor. Pulling in a runtime animation engine to do that
 * would add far more weight than it removes, and this is a security product
 * where every shipped dependency is surface area.
 *
 * The rule every primitive obeys: when motion is disabled, content is still
 * *there*. Nothing may depend on an animation completing to become visible.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type CSSProperties,
  type ReactNode,
} from "react";

/* -------------------------------------------------------- reduced motion -- */

/**
 * The OS motion preference is an external store, so it is read as one rather
 * than copied into state by an effect. That keeps the value available during
 * the first render — which matters, because every primitive below *derives*
 * its output from it instead of writing state when it changes.
 */
function subscribeMotion(onChange: () => void): () => void {
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

const getMotionSnapshot = (): boolean =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** The server cannot know; assume motion is allowed and correct on hydration. */
const getMotionServerSnapshot = (): boolean => false;

export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeMotion,
    getMotionSnapshot,
    getMotionServerSnapshot,
  );
}

/* ---------------------------------------------------------------- reveal -- */

/**
 * How long to wait for an IntersectionObserver callback before showing the
 * content anyway. Long enough that the scroll animation still reads as
 * intentional, short enough that a broken observer is never user-visible.
 */
const FAILSAFE_MS = 1200;

/**
 * Fade + rise an element in the first time it enters the viewport.
 *
 * Deliberately one-shot: re-animating on every scroll pass turns a page into a
 * fidget toy. `delay` is what `Stagger` uses to cascade siblings.
 */
export function Reveal({
  children,
  delay = 0,
  as: Tag = "div",
  className = "",
  style,
}: {
  children: ReactNode;
  delay?: number;
  as?: "div" | "section" | "li" | "article" | "tr";
  className?: string;
  style?: CSSProperties;
}) {
  const reduced = useReducedMotion();
  const ref = useRef<HTMLElement | null>(null);
  const [entered, setEntered] = useState(false);

  // Derived, not synced: with motion disabled, or without IntersectionObserver,
  // the content is simply visible from the first render. Nothing has to write
  // state to reveal it, so content can never be left stranded invisible.
  const unobservable =
    typeof IntersectionObserver === "undefined" && typeof window !== "undefined";
  const shown = entered || reduced || unobservable;

  useEffect(() => {
    if (reduced || unobservable) return;
    const node = ref.current;
    if (!node) return;

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            // Set from an observer callback, not synchronously in the effect.
            setEntered(true);
            observer.disconnect();
          }
        }
      },
      // Start slightly before the element is fully on screen so the motion has
      // finished by the time the reader's eye arrives.
      { rootMargin: "0px 0px -8% 0px", threshold: 0.05 },
    );
    observer.observe(node);

    // Failsafe. Checking that IntersectionObserver *exists* is not the same as
    // knowing it will ever fire — some embedded webviews, prerenderers and
    // automation contexts provide the API but never deliver a callback, which
    // would leave this content invisible forever. Content is never allowed to
    // depend on an animation running, so reveal regardless after a beat.
    const failsafe = setTimeout(() => setEntered(true), FAILSAFE_MS);

    return () => {
      observer.disconnect();
      clearTimeout(failsafe);
    };
  }, [reduced, unobservable]);

  return (
    <Tag
      ref={ref as never}
      className={className}
      style={{
        ...style,
        opacity: shown ? 1 : 0,
        transform: shown || reduced ? "none" : "translate3d(0, 10px, 0)",
        transition: reduced
          ? "opacity 1ms linear"
          : `opacity var(--d-reveal) var(--e-out) ${delay}ms, transform var(--d-reveal) var(--e-out) ${delay}ms`,
        willChange: shown ? "auto" : "opacity, transform",
      }}
    >
      {children}
    </Tag>
  );
}

/** Cascade a list of children, 40ms apart, capped so long lists stay snappy. */
export function Stagger({
  children,
  step = 40,
  max = 10,
  className = "",
}: {
  children: ReactNode[];
  step?: number;
  max?: number;
  className?: string;
}) {
  return (
    <div className={className}>
      {children.map((child, index) => (
        <Reveal key={index} delay={Math.min(index, max) * step}>
          {child}
        </Reveal>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------- counters -- */

/**
 * Tween a number toward its target instead of jump-cutting.
 *
 * Live counters that snap are hard to read and hide the fact that anything
 * changed; a short ease makes an update legible. Uses rAF and stops itself when
 * it arrives so there is no idle timer running behind the page.
 */
export function useTweenedNumber(target: number, durationMs = 520): number {
  const reduced = useReducedMotion();
  const [value, setValue] = useState(target);
  const fromRef = useRef(target);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    if (reduced) {
      // Nothing to animate; the value is derived at the return below.
      fromRef.current = target;
      return;
    }

    const from = fromRef.current;
    if (from === target) return;

    const started = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - started) / durationMs);
      // easeOutCubic — fast start, gentle landing.
      const eased = 1 - Math.pow(1 - t, 3);
      const next = from + (target - from) * eased;
      setValue(next);
      if (t < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = target;
        frameRef.current = null;
      }
    };

    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
      // Preserve where the tween got to, so an interrupted animation continues
      // from its current position rather than snapping back.
      fromRef.current = value;
    };
    // `value` is intentionally excluded: including it would restart the tween
    // on every frame it sets.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, durationMs, reduced]);

  // Derived rather than written by the effect: with motion off, the target is
  // the value, immediately and without an extra render.
  return reduced ? target : value;
}

export function Counter({
  value,
  decimals = 0,
  className = "",
}: {
  value: number;
  decimals?: number;
  className?: string;
}) {
  const tweened = useTweenedNumber(value);
  return (
    <span className={`tnum ${className}`}>{tweened.toFixed(decimals)}</span>
  );
}

/* -------------------------------------------------------------- sequence -- */

/**
 * Drive a step-by-step reveal — the verdict check sequence.
 *
 * Returns how many steps have landed so far. `runId` restarts the sequence, so
 * pressing "Run again" replays it cleanly rather than leaving it complete.
 * Under reduced motion every step lands at once.
 */
export function useSequence(
  steps: number,
  { stepMs = 260, startDelay = 120, runId = 0 }: {
    stepMs?: number;
    startDelay?: number;
    runId?: number | string;
  } = {},
): number {
  const reduced = useReducedMotion();
  const [landed, setLanded] = useState(0);

  useEffect(() => {
    if (reduced) return;
    const timers: ReturnType<typeof setTimeout>[] = [];
    // Step 0 resets the sequence on a re-run; scheduling it rather than
    // calling setLanded(0) inline keeps every write out of the effect commit.
    timers.push(setTimeout(() => setLanded(0), 0));
    for (let i = 1; i <= steps; i++) {
      timers.push(setTimeout(() => setLanded(i), startDelay + i * stepMs));
    }
    return () => timers.forEach(clearTimeout);
  }, [steps, stepMs, startDelay, runId, reduced]);

  // With motion off every step has already landed.
  return reduced ? steps : landed;
}

/* ------------------------------------------------------------------ misc -- */

/**
 * Debounce a rapidly-changing value.
 *
 * Used by the risk tuner: dragging a slider must not fire a server recompute on
 * every pixel. This is a correctness and cost concern as much as a UX one.
 */
export function useDebounced<T>(value: T, delayMs = 260): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

/** Stable id for restarting sequences; increments on demand. */
export function useRunId(): [number, () => void] {
  const [id, setId] = useState(0);
  const bump = useCallback(() => setId((n) => n + 1), []);
  return useMemo(() => [id, bump], [id, bump]);
}
