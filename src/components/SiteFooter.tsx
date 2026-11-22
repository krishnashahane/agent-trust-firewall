import Link from "next/link";

/**
 * The footer.
 *
 * There was previously no footer at all, which meant a visitor who was
 * convinced by the product had nowhere to go: no source, no author, no contact.
 * For a project whose entire claim is "you can check this yourself," a dead end
 * at the bottom of the page is a real gap, not a cosmetic one.
 */

export const GITHUB_PROFILE = "https://github.com/krishnashahane";
export const GITHUB_REPO = "https://github.com/krishnashahane/agent-trust-firewall";
const CONTACT = "mailto:lff99036@gmail.com";

const VERIFY = [
  { label: "Run the attack range", href: "/console/attack-range" },
  { label: "Verify the audit chain", href: "/console/audit" },
  { label: "Read the glossary", href: "/glossary" },
] as const;

export function SiteFooter() {
  return (
    <footer className="mt-20 border-t border-[var(--border)] bg-[var(--bg-raised)]">
      <div className="mx-auto max-w-[1200px] px-4 py-10 sm:px-6">
        <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          <div className="lg:col-span-2">
            <div className="flex items-center gap-2">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
              <span className="text-[13px] font-semibold">Agent Trust Firewall</span>
            </div>
            <p className="mt-3 max-w-md text-[12.5px] leading-relaxed text-[var(--text-muted)]">
              Every verdict here comes from the live engine, and every threat-intel
              finding from a live third-party lookup. The source is public.
            </p>
          </div>

          <nav aria-label="Verify it yourself">
            <h2 className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-faint)]">
              Check it yourself
            </h2>
            <ul className="mt-3 space-y-2">
              {VERIFY.map((item) => (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    prefetch={false}
                    className="link-underline text-[12.5px] text-[var(--text-muted)] transition-colors hover:text-[var(--text)]"
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>

          <nav aria-label="Project and contact">
            <h2 className="text-[11px] font-medium uppercase tracking-[0.06em] text-[var(--text-faint)]">
              Project
            </h2>
            <ul className="mt-3 space-y-2">
              <li>
                <a
                  href={GITHUB_REPO}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1.5 text-[12.5px] text-[var(--text-muted)] transition-colors hover:text-[var(--text)]"
                >
                  <GitHubMark />
                  Source on GitHub
                </a>
              </li>
              <li>
                <a
                  href={CONTACT}
                  className="link-underline text-[12.5px] text-[var(--text-muted)] transition-colors hover:text-[var(--text)]"
                >
                  Get in touch
                </a>
              </li>
              <li>
                <a
                  href={GITHUB_PROFILE}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="link-underline text-[12.5px] text-[var(--text-muted)] transition-colors hover:text-[var(--text)]"
                >
                  More of my work
                </a>
              </li>
            </ul>
          </nav>
        </div>

        <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border)] pt-5">
          <p className="text-[11.5px] text-[var(--text-faint)]">
            Built by{" "}
            <a
              href={GITHUB_PROFILE}
              target="_blank"
              rel="noreferrer noopener"
              className="text-[var(--text-muted)] underline underline-offset-2 hover:text-[var(--text)]"
            >
              Krishna Shahane
            </a>
            . MIT licensed.
          </p>
          <p className="text-[11.5px] text-[var(--text-faint)]">
            Demo agents are synthetic; the cryptography, verdicts and threat
            intelligence are real.
          </p>
        </div>
      </div>
    </footer>
  );
}

function GitHubMark() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}
