import { LiveHeroDemo } from "@/components/LiveHeroDemo";
import { FlowDiagram } from "@/components/FlowDiagram";
import { Reveal } from "@/components/motion";
import { Button } from "@/components/ui";

export const dynamic = "force-dynamic";

export const metadata = {
  alternates: { canonical: "/" },
};

const PROBLEM = [
  {
    n: "01",
    title: "Agents act without a human in the loop",
    body: "They move money, book travel, write to databases and execute code. Nobody is reviewing each individual call.",
  },
  {
    n: "02",
    title: "A compromised agent looks completely normal",
    body: "It holds real credentials and calls real endpoints. Nothing in the request says it has been hijacked or its prompt poisoned.",
  },
  {
    n: "03",
    title: "Nothing checks the handshake",
    body: "An API key proves someone once had a secret. It does not prove that this request, right now, came from the agent you think it did.",
  },
] as const;

const PILLARS = [
  {
    title: "Sealed in transit",
    body: "The agent encrypts each call with a fresh key. Fields it marks sensitive are encrypted to the destination instead — those pass through unreadable to us.",
    accent: "var(--seal)",
  },
  {
    title: "Identity, proved not claimed",
    body: "A zero-knowledge proof of key possession. The key is never sent, and the proof is bound to one challenge and one request.",
    accent: "var(--accent)",
  },
  {
    title: "Scored against live intel",
    body: "Seven signals, including real-time lookups against public threat intelligence for the address the agent is calling from.",
    accent: "var(--flag)",
  },
  {
    title: "Blocked before it runs",
    body: "Revoked key, replayed proof, ungranted capability — these block outright, at any configuration. They are not tunable.",
    accent: "var(--block)",
  },
] as const;

const TEASERS = [
  {
    id: "unenrolled",
    title: "An agent nobody enrolled",
    body: "A caller invents an identity and tries to charge a card — from a real Tor exit node.",
  },
  {
    id: "replay",
    title: "A stolen proof, replayed",
    body: "A valid proof captured off the wire and submitted a second time.",
  },
  {
    id: "escalation",
    title: "Capability escalation",
    body: "A calendar agent, honestly authenticated, reaching for payments.",
  },
] as const;

export default function OverviewPage() {
  return (
    <main className="mx-auto max-w-[1200px] px-4 sm:px-6">
      {/* ------------------------------------------------------------ hero */}
      <section className="grid gap-10 py-14 md:grid-cols-[1.02fr_0.98fr] md:items-center md:gap-12 md:py-20">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--bg-raised)] px-2.5 py-1 text-[11px] text-[var(--text-muted)]">
            <span className="live-dot h-1.5 w-1.5 rounded-full bg-[var(--allow)]" />
            Live engine — every verdict here is computed, not scripted
          </span>

          <h1 className="mt-5 text-[clamp(2rem,6vw,3.25rem)] font-semibold leading-[1.08] tracking-[-0.03em]">
            A firewall for AI agents.
          </h1>

          <p className="mt-5 max-w-xl text-[15px] leading-[1.65] text-[var(--text-muted)]">
            AI agents now book, pay and run code on their own. When one is
            compromised, its requests look exactly like a healthy agent&rsquo;s —
            same credentials, same endpoints, no alarm.{" "}
            <span className="text-[var(--text)]">
              Agent Trust Firewall sits in front of those calls, proves who is
              actually asking, and stops the bad ones before they execute.
            </span>
          </p>

          <div className="mt-7 flex flex-wrap gap-2.5">
            <Button href="/console/attack-range" variant="primary">
              Attack it yourself
            </Button>
            <Button href="/console" variant="secondary">
              Open the live console
            </Button>
          </div>

          <p className="mt-3 text-[12px] text-[var(--text-faint)]">
            No sign-up. The demo fleet is already running.
          </p>
        </div>

        <LiveHeroDemo />
      </section>

      {/* --------------------------------------------------------- problem */}
      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className="text-[clamp(1.25rem,3vw,1.6rem)] font-semibold tracking-[-0.02em]">
            Why this needs to exist
          </h2>
          <p className="mt-2 max-w-2xl text-[14px] leading-relaxed text-[var(--text-muted)]">
            Every company is building agents. Almost nobody is securing the
            handshake between them.
          </p>
        </Reveal>

        <div className="mt-8 grid gap-4 sm:grid-cols-3">
          {PROBLEM.map((item, index) => (
            <Reveal key={item.n} delay={index * 60}>
              <article className="panel h-full px-5 py-5">
                <div className="mono text-[11px] text-[var(--accent)]">{item.n}</div>
                <h3 className="mt-3 text-[14px] font-semibold leading-snug">
                  {item.title}
                </h3>
                <p className="mt-2 text-[13px] leading-relaxed text-[var(--text-muted)]">
                  {item.body}
                </p>
              </article>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------ how it works */}
      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className="text-[clamp(1.25rem,3vw,1.6rem)] font-semibold tracking-[-0.02em]">
            How it works
          </h2>
          <p className="mt-2 max-w-2xl text-[14px] leading-relaxed text-[var(--text-muted)]">
            Every agent call is intercepted at the MCP layer and has to clear four
            checks before it is allowed to run.
          </p>
        </Reveal>

        <div className="mt-8">
          <FlowDiagram />
        </div>

        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {PILLARS.map((item, index) => (
            <Reveal key={item.title} delay={index * 50}>
              <article className="panel h-full px-5 py-5">
                <div
                  aria-hidden="true"
                  className="h-[3px] w-7 rounded-full"
                  style={{ background: item.accent }}
                />
                <h3 className="mt-3.5 text-[13.5px] font-semibold">{item.title}</h3>
                <p className="mt-2 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                  {item.body}
                </p>
              </article>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ---------------------------------------------------------- teasers */}
      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className="text-[clamp(1.25rem,3vw,1.6rem)] font-semibold tracking-[-0.02em]">
            See it stop something
          </h2>
          <p className="mt-2 max-w-2xl text-[14px] leading-relaxed text-[var(--text-muted)]">
            Real attacks against the live engine — a genuinely forged key, a
            genuinely replayed proof. Pick one and watch what happens.
          </p>
        </Reveal>

        <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {TEASERS.map((item, index) => (
            <Reveal key={item.id} delay={index * 60}>
              <a
                href={`/console/attack-range?scenario=${item.id}`}
                className="panel card-interactive group flex h-full flex-col px-5 py-5"
              >
                <h3 className="text-[13.5px] font-semibold">{item.title}</h3>
                <p className="mt-2 flex-1 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                  {item.body}
                </p>
                <span className="mt-4 inline-flex items-center gap-1.5 text-[12px] font-medium text-[var(--accent)]">
                  Run it
                  <span
                    aria-hidden="true"
                    className="transition-transform duration-[var(--d)] group-hover:translate-x-0.5"
                  >
                    →
                  </span>
                </span>
              </a>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------ honest scope */}
      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className="text-[clamp(1.25rem,3vw,1.6rem)] font-semibold tracking-[-0.02em]">
            What this is, and what it isn&rsquo;t
          </h2>
          <p className="mt-2 max-w-2xl text-[14px] leading-relaxed text-[var(--text-muted)]">
            A security product should be easy to check and honest about its edges.
            Both columns below are part of the pitch.
          </p>
        </Reveal>

        <div className="mt-8 grid gap-4 md:grid-cols-2">
          <Reveal>
            <div className="panel h-full px-5 py-5">
              <h3 className="text-[13.5px] font-semibold text-[var(--allow)]">
                Real, and you can check it
              </h3>
              <ul className="mt-3.5 space-y-2.5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                <li>
                  Genuine cryptography: Schnorr zero-knowledge proofs and Merkle
                  capability proofs over ed25519, X25519 with XChaCha20-Poly1305 for
                  encryption. Audited primitives, no hand-rolled maths.
                </li>
                <li>
                  External findings come from live lookups against public threat
                  intelligence, and every one is labelled with its provider so you
                  can check the claim yourself.
                </li>
                <li>
                  The audit log is hash-chained. You can forge a record on the Audit
                  page and watch the integrity check catch it.
                </li>
              </ul>
            </div>
          </Reveal>

          <Reveal delay={60}>
            <div className="panel h-full px-5 py-5">
              <h3 className="text-[13.5px] font-semibold text-[var(--flag)]">
                Scoped, and we&rsquo;d rather say so
              </h3>
              <ul className="mt-3.5 space-y-2.5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                <li>
                  An MCP-ecosystem MVP, not an internet-scale agent mesh. It secures
                  calls that pass through the interceptor.
                </li>
                <li>
                  Storage is in-process, so the traffic feed and audit log start fresh
                  whenever the server goes cold. Nothing on this site claims otherwise.
                  The storage layer is an interface; a database drops in behind it.
                </li>
                <li>
                  The agents in the demo fleet are synthetic. Their keys, proofs,
                  verdicts and origin addresses are real — the addresses are live
                  cloud hosts, and the intel shown about them is fetched at request
                  time, so you can check any of it yourself.
                </li>
                <li>
                  A firewall must read a request to score it, so ATF is a trusted
                  endpoint for the outer envelope. Only fields sealed to the
                  destination stay unreadable to it.
                </li>
              </ul>
            </div>
          </Reveal>
        </div>

        <p className="mt-6 text-[12px] text-[var(--text-faint)]">
          Unfamiliar with a term?{" "}
          <a
            href="/glossary"
            className="text-[var(--accent)] underline underline-offset-2"
          >
            The glossary
          </a>{" "}
          explains every one in plain language.
        </p>
      </section>
    </main>
  );
}
