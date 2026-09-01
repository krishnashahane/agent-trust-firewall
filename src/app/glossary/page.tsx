import { PageHeader } from "@/components/PageHeader";
import { Glossary, type Term } from "@/components/Glossary";

export const metadata = { title: "Glossary — Agent Trust Firewall" };

/**
 * Every piece of jargon this product uses, explained the way you would explain
 * it to a colleague who does not work in security. If a term appears anywhere
 * in the app and is not on this page, that is a bug.
 */
const TERMS: Term[] = [
  {
    term: "AI agent",
    plain: "A program that decides what to do next on its own.",
    detail:
      "Rather than following a fixed script, it picks which tools to call and when — booking, paying, querying, writing code. That autonomy is what makes securing its outbound calls a distinct problem.",
  },
  {
    term: "MCP (Model Context Protocol)",
    plain: "The standard way agents call tools.",
    detail:
      "An open protocol for connecting agents to tools and data. Because agent traffic funnels through it, it is the natural place to put a firewall — the same reason network firewalls sit on the network.",
  },
  {
    term: "Zero-knowledge proof",
    plain: "Proving you know a secret without revealing it.",
    detail:
      "ATF uses a Schnorr proof: the agent demonstrates it holds the private key matching its enrolled public key, using maths that convinces the firewall while transmitting nothing an eavesdropper could reuse. The key never crosses the wire, not even encrypted.",
  },
  {
    term: "Challenge / nonce",
    plain: "A one-time number that makes a proof unrepeatable.",
    detail:
      "Before making a call an agent asks for a challenge. Its proof is built around that challenge and around the specific request, and the challenge is spent the moment it is used. Capture the proof and replay it and you are replaying a spent challenge — which fails.",
  },
  {
    term: "Replay attack",
    plain: "Reusing a valid message you intercepted.",
    detail:
      "The classic attack against any 'prove yourself' scheme. If a proof is valid forever, stealing it once is as good as stealing the key. Single-use challenges are the defence.",
  },
  {
    term: "Capability",
    plain: "One specific permission an agent holds.",
    detail:
      "Like 'payments:refund' or 'calendar:*'. An agent proves it holds the one capability a call needs, rather than presenting its whole list — so a compromised call reveals as little as possible about what else that agent could do.",
  },
  {
    term: "Merkle proof",
    plain: "Proving one item is in a set, without showing the set.",
    detail:
      "Capabilities are hashed into a tree whose root is stored at enrolment. An agent can prove a single capability is in that tree by showing a short path of hashes. The firewall learns that one permission and nothing else.",
  },
  {
    term: "Capability escalation",
    plain: "Reaching for authority you were not given.",
    detail:
      "An agent with calendar access trying to charge a card. Its identity may be entirely genuine — which is precisely why identity alone is not enough, and why capability is checked separately.",
  },
  {
    term: "End-to-end encryption",
    plain: "Only the intended recipient can read it.",
    detail:
      "Agent calls are sealed with a fresh key each time (X25519 key exchange, XChaCha20-Poly1305 encryption). Fields an agent marks sensitive are sealed to the destination instead of to the firewall, so they pass through ATF unreadable.",
  },
  {
    term: "Forward secrecy",
    plain: "Old traffic stays private even if a key leaks later.",
    detail:
      "Because each call uses a throwaway key, an attacker who steals a long-term key tomorrow cannot go back and decrypt what was captured today.",
  },
  {
    term: "Risk score",
    plain: "How suspicious this specific call looks, 0 to 100.",
    detail:
      "Seven signals — identity posture, request context, behaviour baseline, request rate, payload contents, recent reputation and live external intelligence — each contribute points. Every point traces back to a named reason, so an operator can argue with the verdict rather than just receiving it.",
  },
  {
    term: "Trust score",
    plain: "How an agent has been behaving lately, 0 to 100.",
    detail:
      "The inverse of its recent average risk. High trust means its last hour looked ordinary. It is context, not permission: a trusted agent making a dangerous request still gets stopped.",
  },
  {
    term: "Hard rule",
    plain: "A failure no score can override.",
    detail:
      "Revoked key, unverified proof, replayed challenge, ungranted capability. These block outright at any threshold setting, because a security rule that a slider can switch off is not a rule.",
  },
  {
    term: "Prompt injection",
    plain: "Text written to hijack an AI's instructions.",
    detail:
      "Phrasing like 'ignore all previous instructions' smuggled into ordinary-looking data, aimed at the model on the receiving end. ATF scans argument text for these patterns before forwarding a call.",
  },
  {
    term: "Exfiltration",
    plain: "Data being smuggled out inside a normal-looking request.",
    detail:
      "An API key tucked into a field, or a large blob of encoded data attached to a small lookup. Size and randomness are measured against what that kind of call usually carries.",
  },
  {
    term: "Hash chain",
    plain: "A log where each entry seals the one before it.",
    detail:
      "Change any past record and every hash after it stops matching. It makes an audit log append-only in a way you can verify yourself, rather than one you have to trust the operator about.",
  },
  {
    term: "OSINT",
    plain: "Intelligence gathered from public sources.",
    detail:
      "Open-source intelligence. Here it means live lookups against public threat-intelligence services — GreyNoise, Shodan — for the address an agent is calling from. Every finding shown in this product names its provider and links to the source so you can check it independently.",
  },
  {
    term: "Tor exit node",
    plain: "The last hop before anonymised traffic reaches the open internet.",
    detail:
      "Tor has legitimate uses, so this is not proof of malice. But an autonomous agent that normally calls from your own infrastructure suddenly calling from an anonymising relay is a meaningful change, and the firewall weighs it as one.",
  },
  {
    term: "Zero trust",
    plain: "Verify every request; trust nothing by position.",
    detail:
      "Being inside the network, or having been fine a moment ago, earns a caller nothing. Each individual call is checked on its own merits.",
  },
  {
    term: "Fail closed",
    plain: "When something goes wrong, deny rather than allow.",
    detail:
      "If a check errors or a value cannot be parsed, ATF blocks. The alternative — failing open — turns every bug into a security hole.",
  },
];

export default function GlossaryPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
      <PageHeader
        title="Glossary"
        lede="Security has a lot of jargon, and most of it hides a simple idea. Here is every term this product uses, in plain language first."
      />
      <Glossary terms={TERMS} />
    </main>
  );
}
