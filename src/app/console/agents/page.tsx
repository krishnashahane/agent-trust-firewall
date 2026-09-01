import { AgentsView } from "@/components/AgentsView";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = {
  title: "Agents",
  description: "The enrolled agent fleet, their capabilities, trust scores and live threat intelligence.",
  alternates: { canonical: "/console/agents" },
  openGraph: {
    title: "Agents · Agent Trust Firewall",
    description: "The enrolled agent fleet, their capabilities, trust scores and live threat intelligence.",
    url: "/console/agents",
    // Declaring openGraph here replaces the parent block entirely, so the
    // image has to be named again or the card ships with no picture.
    images: ["/opengraph-image"],
  },
  twitter: {
    title: "Agents · Agent Trust Firewall",
    description: "The enrolled agent fleet, their capabilities, trust scores and live threat intelligence.",
    images: ["/opengraph-image"],
  },
};

export default function AgentsPage() {
  return (
    <main className="mx-auto max-w-[900px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Agents"
        lede="The fleet the firewall knows about. Enrolment records a public key and a commitment to what each agent may do — never a secret, and never the capability list itself."
      />
      <AgentsView />
    </main>
  );
}
