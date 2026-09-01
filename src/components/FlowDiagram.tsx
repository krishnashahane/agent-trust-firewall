"use client";

import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "@/components/motion";

/**
 * The architecture diagram.
 *
 * A call travels left to right through the four checks when the diagram scrolls
 * into view, so the reader watches the architecture work rather than reading a
 * static picture of it. Inline SVG on theme tokens: one asset, correct in both
 * themes, no image request.
 *
 * The animation is decoration only in the strict sense that the text below
 * carries the same information — a reader with motion disabled, or a screen
 * reader user, loses nothing.
 */

const STAGES = [
  { key: "identity", label: "Identity", sub: "ZK proof", x: 236 },
  { key: "capability", label: "Capability", sub: "Merkle proof", x: 330 },
  { key: "risk", label: "Risk", sub: "7 signals", x: 424 },
  { key: "policy", label: "Policy", sub: "hard rules", x: 518 },
] as const;

export function FlowDiagram() {
  const reduced = useReducedMotion();
  const ref = useRef<HTMLElement | null>(null);
  const [walked, setWalked] = useState(-1);

  // Derived: with motion off, or without IntersectionObserver, the diagram is
  // simply shown complete. No state write is needed to make it readable.
  const unobservable =
    typeof IntersectionObserver === "undefined" && typeof window !== "undefined";
  const active = reduced || unobservable ? STAGES.length : walked;

  useEffect(() => {
    if (reduced || unobservable) return;
    const node = ref.current;
    if (!node) return;

    const timers: ReturnType<typeof setTimeout>[] = [];
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          observer.disconnect();
          // Walk the call through each stage in turn.
          for (let i = 0; i <= STAGES.length; i++) {
            timers.push(setTimeout(() => setWalked(i), 220 + i * 340));
          }
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(node);

    // Failsafe: an IntersectionObserver that exists but never fires must not
    // leave the diagram permanently dimmed. See the note in motion/index.tsx.
    timers.push(setTimeout(() => setWalked(STAGES.length), 2000));

    return () => {
      observer.disconnect();
      timers.forEach(clearTimeout);
    };
  }, [reduced, unobservable]);

  const reached = (index: number) => active >= index;

  return (
    <figure ref={ref as never} className="panel px-4 py-6 sm:px-6">
      <div className="scroll-x">
        <svg
          viewBox="0 0 880 176"
          className="mx-auto block h-auto w-full min-w-[660px] max-w-[880px]"
          role="img"
          aria-label="An agent's call is encrypted, then checked by the firewall for identity, capability, risk and policy, before reaching the API. Calls that fail are blocked at the firewall and never reach it."
        >
          <defs>
            <marker
              id="atf-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M0 0 L10 5 L0 10 z" fill="var(--border-strong)" />
            </marker>
            <marker
              id="atf-arrow-block"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M0 0 L10 5 L0 10 z" fill="var(--block)" />
            </marker>
          </defs>

          {/* agent */}
          <g>
            <rect
              x="8"
              y="48"
              width="124"
              height="56"
              rx="10"
              fill="var(--bg-inset)"
              stroke="var(--border-strong)"
            />
            <text x="70" y="72" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="var(--text)">
              AI agent
            </text>
            <text x="70" y="89" textAnchor="middle" fontSize="10.5" fill="var(--text-muted)">
              holds its own key
            </text>
          </g>

          {/* encrypted hop — the dash marches once the call departs */}
          <line
            x1="134"
            y1="76"
            x2="222"
            y2="76"
            stroke="var(--seal)"
            strokeWidth="1.8"
            strokeDasharray="5 4"
            markerEnd="url(#atf-arrow)"
            style={{
              opacity: reached(0) ? 1 : 0.25,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          />
          <text
            x="178"
            y="65"
            textAnchor="middle"
            fontSize="10"
            fontWeight="600"
            fill="var(--seal)"
            style={{
              opacity: reached(0) ? 1 : 0.25,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          >
            encrypted
          </text>

          {/* firewall */}
          <rect
            x="226"
            y="16"
            width="380"
            height="120"
            rx="14"
            fill="var(--bg-raised)"
            stroke="var(--accent)"
            strokeWidth="1.4"
          />
          <text
            x="416"
            y="37"
            textAnchor="middle"
            fontSize="10.5"
            fontWeight="700"
            fill="var(--accent)"
            letterSpacing="0.8"
          >
            AGENT TRUST FIREWALL
          </text>

          {STAGES.map((stage, index) => {
            const on = reached(index + 1);
            return (
              <g key={stage.key}>
                <rect
                  x={stage.x}
                  y="52"
                  width="80"
                  height="56"
                  rx="8"
                  fill={on ? "var(--accent-soft)" : "var(--bg-inset)"}
                  stroke={on ? "var(--accent)" : "var(--border)"}
                  style={{
                    transition:
                      "fill var(--d-slow) var(--e-out), stroke var(--d-slow) var(--e-out)",
                  }}
                />
                <text
                  x={stage.x + 40}
                  y="76"
                  textAnchor="middle"
                  fontSize="11.5"
                  fontWeight="600"
                  fill={on ? "var(--accent)" : "var(--text)"}
                  style={{ transition: "fill var(--d-slow) var(--e-out)" }}
                >
                  {stage.label}
                </text>
                <text
                  x={stage.x + 40}
                  y="93"
                  textAnchor="middle"
                  fontSize="9.5"
                  fill="var(--text-faint)"
                >
                  {stage.sub}
                </text>
              </g>
            );
          })}

          {/* allowed exit */}
          <line
            x1="608"
            y1="76"
            x2="694"
            y2="76"
            stroke="var(--allow)"
            strokeWidth="1.8"
            markerEnd="url(#atf-arrow)"
            style={{
              opacity: reached(STAGES.length) ? 1 : 0.2,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          />
          <text
            x="651"
            y="65"
            textAnchor="middle"
            fontSize="10"
            fontWeight="600"
            fill="var(--allow)"
            style={{
              opacity: reached(STAGES.length) ? 1 : 0.2,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          >
            allowed
          </text>

          <rect
            x="698"
            y="48"
            width="174"
            height="56"
            rx="10"
            fill="var(--bg-inset)"
            stroke="var(--border-strong)"
          />
          <text x="785" y="72" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="var(--text)">
            API / other agent
          </text>
          <text x="785" y="89" textAnchor="middle" fontSize="10.5" fill="var(--text-muted)">
            the thing being protected
          </text>

          {/* blocked exit */}
          <path
            d="M416 136 L416 158"
            stroke="var(--block)"
            strokeWidth="1.8"
            markerEnd="url(#atf-arrow-block)"
            style={{
              opacity: reached(2) ? 1 : 0.2,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          />
          <text
            x="430"
            y="163"
            fontSize="10"
            fontWeight="600"
            fill="var(--block)"
            style={{
              opacity: reached(2) ? 1 : 0.2,
              transition: "opacity var(--d-slow) var(--e-out)",
            }}
          >
            blocked — never reaches the API
          </text>
        </svg>
      </div>

      <figcaption className="mt-6 grid gap-3 text-[12.5px] leading-relaxed text-[var(--text-muted)] sm:grid-cols-2">
        <p>
          <b className="font-medium text-[var(--text)]">Encrypted.</b> The agent
          seals the call with a one-time key, so nothing readable crosses the wire.
        </p>
        <p>
          <b className="font-medium text-[var(--text)]">Identity.</b> It proves it
          holds its secret key without sending it, against a challenge good for
          exactly one request.
        </p>
        <p>
          <b className="font-medium text-[var(--text)]">Capability.</b> It proves
          the one permission this call needs, revealing nothing about the rest of
          its authority.
        </p>
        <p>
          <b className="font-medium text-[var(--text)]">Risk and policy.</b> Seven
          signals — including live external threat intelligence — produce an
          explained score; hard rules block regardless of where it lands.
        </p>
      </figcaption>
    </figure>
  );
}
