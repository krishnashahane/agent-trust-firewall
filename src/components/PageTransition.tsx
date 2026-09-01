"use client";

import { usePathname } from "next/navigation";
import { useReducedMotion } from "@/components/motion";

/**
 * A short settle on route change.
 *
 * Keyed on the pathname, so React remounts the subtree and the CSS animation
 * replays. Deliberately 260ms and opacity+translate only: long enough to read
 * as arriving somewhere, short enough that nobody ever waits for it, and cheap
 * enough to stay on the compositor.
 *
 * There is no exit animation on purpose. Playing one would mean holding the old
 * page on screen after the user has already asked for a new one, which trades
 * their time for our polish.
 */
export function PageTransition({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const reduced = useReducedMotion();

  if (reduced) return <>{children}</>;

  return (
    <div key={pathname} className="page-in">
      {children}
    </div>
  );
}
