import { TrafficConsole } from "@/components/TrafficConsole";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = { title: "Console — Agent Trust Firewall" };

export default function ConsolePage() {
  return (
    <main className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Console"
        lede="Everything the firewall has intercepted, as it happens. Each row is one agent call that was verified, scored and either allowed through or stopped."
      />
      <TrafficConsole />
    </main>
  );
}
