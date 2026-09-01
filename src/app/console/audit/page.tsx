import { AuditView } from "@/components/AuditView";
import { PageHeader } from "@/components/PageHeader";

export const dynamic = "force-dynamic";
export const metadata = { title: "Audit — Agent Trust Firewall" };

export default function AuditPage() {
  return (
    <main className="mx-auto max-w-[1100px] px-4 py-8 sm:px-6">
      <PageHeader
        title="Audit"
        lede="Every decision the firewall made, in a log that cannot be quietly rewritten. Try to forge a record and watch the integrity check show you exactly where it broke."
      />
      <AuditView />
    </main>
  );
}
