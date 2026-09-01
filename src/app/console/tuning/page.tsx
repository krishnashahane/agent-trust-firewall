import { RiskTuner } from "@/components/RiskTuner";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = {
  title: "Risk tuning",
  description: "Tune signal weights and thresholds in a personal sandbox and re-score recent traffic.",
  alternates: { canonical: "/console/tuning" },
  openGraph: { title: "Risk tuning · Agent Trust Firewall", description: "Tune signal weights and thresholds in a personal sandbox and re-score recent traffic.", url: "/console/tuning" },
};

export default function TuningPage() {
  return (
    <main className="mx-auto max-w-[1100px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Risk tuning"
        lede="Adjust what the firewall weighs and where it draws the line, then see what that would have done to traffic it has already seen."
      />
      <RiskTuner />
    </main>
  );
}
