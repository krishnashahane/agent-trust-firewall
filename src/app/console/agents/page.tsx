import { AgentsView } from "@/components/AgentsView";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = { title: "Agents — Agent Trust Firewall" };

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
