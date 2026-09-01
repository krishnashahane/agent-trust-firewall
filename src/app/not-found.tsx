import Link from "next/link";

export const metadata = { title: "Not found — Agent Trust Firewall" };

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-[60vh] max-w-[560px] flex-col items-center justify-center px-4 text-center">
      <div
        aria-hidden="true"
        className="mb-4 h-9 w-9 rounded-full border border-[var(--border-strong)] bg-[var(--bg-sunken)]"
      />
      <h1 className="text-[18px] font-semibold tracking-[-0.02em]">
        There&rsquo;s nothing at this address
      </h1>
      <p className="mt-2 text-[13.5px] leading-relaxed text-[var(--text-muted)]">
        The page you asked for doesn&rsquo;t exist. The console, attack range and
        audit log are all reachable from the navigation above.
      </p>
      <Link
        href="/"
        prefetch={false}
        className="tap mt-5 rounded-[var(--r)] bg-[var(--accent)] px-3.5 py-2 text-[13px] font-medium text-[var(--accent-text)] transition-opacity hover:opacity-90"
      >
        Back to overview
      </Link>
    </main>
  );
}
