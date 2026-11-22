import { TrafficConsole } from "@/components/TrafficConsole";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = {
  title: "Console",
  description: "Live traffic through the firewall: every intercepted agent call, its risk score and its verdict.",
  alternates: { canonical: "/console" },
  openGraph: {
    title: "Console · Agent Trust Firewall",
    description: "Live traffic through the firewall: every intercepted agent call, its risk score and its verdict.",
    url: "/console",
    // Declaring openGraph here replaces the parent block entirely, so the
    // image has to be named again or the card ships with no picture.
    images: ["/opengraph-image"],
  },
  twitter: {
    title: "Console · Agent Trust Firewall",
    description: "Live traffic through the firewall: every intercepted agent call, its risk score and its verdict.",
    images: ["/opengraph-image"],
  },
};

export default function ConsolePage() {
  return (
    <main className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Console"
        lede="Every request an AI agent sent through the firewall, newest first: who asked, what for, and whether it was allowed, held for a person to review, or blocked — with the reason. The agents are demo agents; every verdict is computed live."
      />
      <TrafficConsole />
    </main>
  );
}
