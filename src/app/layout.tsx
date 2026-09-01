import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import { ThemeToggle } from "@/components/ThemeToggle";
import { MobileNav, Nav } from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Agent Trust Firewall",
  description:
    "A firewall for AI agents. It proves who is calling — cryptographically — scores the request against live threat intelligence, and blocks rogue agent calls before they run.",
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: "#fcfcfd",
};

/**
 * Applies the saved theme before first paint, or the page flashes light and
 * then repaints dark for anyone who chose dark.
 *
 * Light is the default: this reads only the explicit choice and ignores the OS
 * preference entirely, matching the CSS, where dark exists solely under
 * [data-theme="dark"]. Needs the per-request CSP nonce from proxy.ts.
 */
const themeScript = `(function(){try{var t=localStorage.getItem("atf-theme");if(t==="dark"){document.documentElement.setAttribute("data-theme","dark")}}catch(e){}})();`;

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-screen antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-[60] focus:rounded-[var(--r)] focus:bg-[var(--accent)] focus:px-3 focus:py-2 focus:text-[13px] focus:font-medium focus:text-[var(--accent-text)]"
        >
          Skip to content
        </a>

        <header className="sticky top-0 z-40 border-b border-[var(--border)] bg-[var(--bg-raised)]/88 backdrop-blur-md">
          <div className="mx-auto flex h-14 max-w-[1200px] items-center gap-4 px-4 sm:px-6">
            <Link
              href="/"
              className="flex shrink-0 items-center gap-2 text-[14px] font-semibold tracking-tight"
            >
              <Mark />
              <span className="hidden sm:inline">Agent Trust Firewall</span>
              <span className="sm:hidden">ATF</span>
            </Link>

            <Nav />

            <div className="ml-auto flex shrink-0 items-center gap-1.5">
              <ThemeToggle />
              <MobileNav />
            </div>
          </div>
        </header>

        <div id="main">{children}</div>

        <footer className="mt-20 border-t border-[var(--border)]">
          <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
            <p className="text-[12px] leading-relaxed text-[var(--text-faint)]">
              Every verdict on this site was produced by the live engine, and every
              external finding by a live third-party lookup. Nothing is pre-recorded.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}

function Mark() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.6 5.4v6.2c0 4.6 3 8.7 7.4 10 4.4-1.3 7.4-5.4 7.4-10V5.4L12 2.5Z"
        stroke="var(--accent)"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="M8.9 12.2l2.1 2.1 4.1-4.3"
        stroke="var(--accent)"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
