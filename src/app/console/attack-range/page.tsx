import { Suspense } from "react";
import { AttackRange } from "@/components/AttackRange";
import { PageHeader } from "@/components/PageHeader";
import { SealedFieldDemo } from "@/components/SealedFieldDemo";
import { Skeleton } from "@/components/ui";

export const dynamic = "force-dynamic";
export const metadata = {
  title: "Attack range",
  description: "Run real adversaries at the firewall — forged keys, replayed proofs, capability escalation.",
  alternates: { canonical: "/console/attack-range" },
  openGraph: {
    title: "Attack range · Agent Trust Firewall",
    description: "Run real adversaries at the firewall — forged keys, replayed proofs, capability escalation.",
    url: "/console/attack-range",
    // Declaring openGraph here replaces the parent block entirely, so the
    // image has to be named again or the card ships with no picture.
    images: ["/opengraph-image"],
  },
  twitter: {
    title: "Attack range · Agent Trust Firewall",
    description: "Run real adversaries at the firewall — forged keys, replayed proofs, capability escalation.",
    images: ["/opengraph-image"],
  },
};

export default function AttackRangePage() {
  return (
    <main className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Attack range"
        lede="Pick an attack and send it through the live firewall: an agent nobody approved, a stolen request sent again, an agent reaching beyond its permissions. Each is built for real, so the verdict you see is computed, not recorded."
      />
      <Suspense
        fallback={
          <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
            <div className="panel px-4 py-5 sm:px-5">
              <Skeleton width="46%" height={13} />
              <div className="mt-4 space-y-3">
                {Array.from({ length: 6 }, (_, i) => (
                  <Skeleton key={i} width="100%" height={34} />
                ))}
              </div>
            </div>
            <div className="panel px-4 py-5 sm:px-5">
              <Skeleton width="32%" height={13} />
              <Skeleton width="100%" height={120} className="mt-4" />
            </div>
          </div>
        }
      >
        <AttackRange />
      </Suspense>

      <div className="mt-4">
        <SealedFieldDemo />
      </div>
    </main>
  );
}
