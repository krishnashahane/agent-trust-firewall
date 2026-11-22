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
    title: "Nobody reviews each call",
    body: "Agents move money, book travel, write to databases and run code without a human approving every request.",
  },
  {
    title: "A hijacked agent looks healthy",
    body: "It still holds valid credentials and calls the usual endpoints. Nothing in the request says its prompt was poisoned.",
  },
  {
    title: "API keys prove too little",
    body: "A key shows someone once had a secret. It does not show that this request, right now, came from the agent you enrolled.",
  },
] as const;

const PLAIN = [
  {
    title: "Checks the ID",
    body: "Every AI agent has a secret key. Before anything runs, it must prove it holds that key — a copied or stolen request will not pass.",
  },
  {
    title: "Checks the ticket",
    body: "Each agent is approved for specific jobs, like booking meetings. If a booking agent suddenly tries to make a payment, it is stopped.",
  },
  {
    title: "Scans the bag",
    body: "The request is scored for warning signs: odd behaviour, hidden instructions, leaked passwords, known bad addresses.",
  },
  {
    title: "Keeps a sealed logbook",
    body: "Every decision is written to a log that shows if anyone edits or deletes an entry later — even whoever runs the server.",
  },
] as const;

const LIMITS = [
  "It protects calls that pass through it. An agent that bypasses the gateway is not covered.",
  "The demo agents are synthetic. Their keys, proofs, verdicts and the threat intel on their addresses are real and computed live.",
  "To score a request, the firewall has to read it. Only fields the agent seals to the destination stay hidden from it.",
  "Payload inspection is heuristic, so a detection escalates to a human review rather than blocking on its own.",
  "Without DATABASE_URL, history lives in memory and resets on restart. /api/health reports which store is active.",
] as const;

const sectionTitle = "text-[clamp(1.25rem,3vw,1.6rem)] font-semibold tracking-[-0.02em]";
const sectionLede = "mt-2 max-w-2xl text-[14px] leading-relaxed text-[var(--text-muted)]";

export default function OverviewPage() {
  return (
    <main className="mx-auto max-w-[1200px] px-4 sm:px-6">
      <section className="grid gap-10 py-14 md:grid-cols-[1.02fr_0.98fr] md:items-center md:gap-12 md:py-20">
        <div>
          <h1 className="text-[clamp(2rem,6vw,3.25rem)] font-semibold leading-[1.08] tracking-[-0.03em]">
            A firewall for AI agents.
          </h1>

          <p className="mt-5 max-w-xl text-[15px] leading-[1.65] text-[var(--text-muted)]">
            When an agent is compromised, its requests look exactly like a
            healthy one&rsquo;s.{" "}
            <span className="text-[var(--text)]">
              Agent Trust Firewall sits in front of every call, proves which agent
              is asking and what it is allowed to do, and blocks the bad ones
              before they run.
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
            No sign-up. A demo fleet of six agents is already running.
          </p>
        </div>

        <LiveHeroDemo />
      </section>

      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className={sectionTitle}>In plain terms</h2>
          <p className={sectionLede}>
            Think of it as airport security for AI agents. Every request an agent
            makes is stopped at the gate and checked four ways before it is allowed
            through. The result is one of three words:{" "}
            <b className="font-medium text-[var(--allow)]">Allowed</b>,{" "}
            <b className="font-medium text-[var(--flag)]">Flagged</b> (held for a person
            to review) or <b className="font-medium text-[var(--block)]">Blocked</b>.
          </p>
        </Reveal>

        <dl className="mt-6 grid gap-x-10 gap-y-6 sm:grid-cols-2 lg:grid-cols-4">
          {PLAIN.map((item, index) => (
            <Reveal key={item.title} delay={index * 60}>
              <dt className="text-[14px] font-semibold leading-snug">{item.title}</dt>
              <dd className="mt-1.5 text-[13px] leading-relaxed text-[var(--text-muted)]">
                {item.body}
              </dd>
            </Reveal>
          ))}
        </dl>
      </section>

      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className={sectionTitle}>The problem</h2>
        </Reveal>

        <dl className="mt-6 grid gap-x-10 gap-y-6 sm:grid-cols-3">
          {PROBLEM.map((item, index) => (
            <Reveal key={item.title} delay={index * 60}>
              <dt className="text-[14px] font-semibold leading-snug">{item.title}</dt>
              <dd className="mt-1.5 text-[13px] leading-relaxed text-[var(--text-muted)]">
                {item.body}
              </dd>
            </Reveal>
          ))}
        </dl>
      </section>

      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className={sectionTitle}>How it works</h2>
          <p className={sectionLede}>
            Every call clears four checks before it reaches the tool. Fail any hard
            check and the call is blocked, whatever the risk score says.
          </p>
        </Reveal>

        <div className="mt-8">
          <FlowDiagram />
        </div>
      </section>

      <section className="border-t border-[var(--border)] py-14 md:py-16">
        <Reveal>
          <h2 className={sectionTitle}>Limits</h2>
          <p className={sectionLede}>
            What it does not do, stated up front.
          </p>
        </Reveal>

        <ul className="mt-6 max-w-3xl list-disc space-y-2.5 pl-5 text-[13px] leading-relaxed text-[var(--text-muted)] marker:text-[var(--text-faint)]">
          {LIMITS.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>

        <p className="mt-8 text-[12px] text-[var(--text-faint)]">
          New to a term?{" "}
          <a href="/glossary" className="text-[var(--accent)] underline underline-offset-2">
            The glossary
          </a>{" "}
          explains each one in plain language.
        </p>
      </section>
    </main>
  );
}
