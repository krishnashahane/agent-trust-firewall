"use client";

import { useId } from "react";
import { useReducedMotion } from "@/components/motion";

/**
 * A trend line over real recorded values.
 *
 * Point-in-time numbers hide the story: "72 allowed" says nothing about whether
 * risk is climbing. This plots the actual scores the engine produced, oldest to
 * newest, so a reader can see movement rather than a single figure.
 *
 * It draws nothing when there is nothing to draw. A sparkline invented from one
 * data point would be decoration pretending to be information, which is exactly
 * the failure mode this product argues against everywhere else.
 */
export function Sparkline({
  values,
  width = 132,
  height = 30,
  color = "var(--accent)",
  label,
}: {
  /** oldest → newest */
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  label: string;
}) {
  const gradientId = useId();
  const reduced = useReducedMotion();

  if (values.length < 2) {
    return (
      <div
        className="flex items-center text-[11px] text-[var(--text-faint)]"
        style={{ height }}
      >
        Not enough history yet
      </div>
    );
  }

  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = Math.max(1, max - min);
  const stepX = width / (values.length - 1);

  const points = values.map((value, index) => {
    const x = index * stepX;
    // Inset by 2px top and bottom so a peak is not clipped by the viewBox.
    const y = height - 2 - ((value - min) / span) * (height - 4);
    return [x, y] as const;
  });

  const line = points
    .map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ");
  const area = `${line} L${width},${height} L0,${height} Z`;
  const last = points[points.length - 1] as readonly [number, number];

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={label}
      style={{ display: "block", overflow: "visible" }}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.18" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>

      <path d={area} fill={`url(#${gradientId})`} />
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={
          reduced
            ? undefined
            : {
                // Draw the line on rather than popping it in. pathLength
                // normalises the dash maths regardless of the real path length.
                strokeDasharray: 1,
                strokeDashoffset: 0,
                animation: "atf-draw 700ms var(--e-out) both",
              }
        }
        pathLength={1}
      />
      {/* The newest reading gets a dot: it is the one the eye should land on. */}
      <circle cx={last[0]} cy={last[1]} r="2.4" fill={color} />
    </svg>
  );
}
