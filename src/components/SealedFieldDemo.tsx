"use client";

import { useState } from "react";
import {
  Button,
  LoadingRegion,
  Panel,
  Skeleton,
  VerdictBadge,
} from "@/components/ui";
import type { Decision } from "@/lib/atf/types";

interface SealedDemo {
  decision: Decision;
  ciphertextPreview: string;
  descriptor: { bytes: number; entropy: number; shape: string };
  requestDigest: string;
  capabilityRoot: string;
  capabilityProofLength: number;
}

/**
 * End-to-end encryption, demonstrated rather than claimed.
 *
 * A card number is sealed to the destination's key, passed through the
 * firewall, scored, and comes back out still unreadable here. The two panels
 * side by side are the argument: what ATF holds (ciphertext) next to what it
 * scored instead (a size/entropy/shape descriptor it verified against that
 * ciphertext).
 */
export function SealedFieldDemo() {
  const [result, setResult] = useState<SealedDemo | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(false);

  const run = async () => {
    setRunning(true);
    setError(false);
    try {
      const response = await fetch("/api/sealed-demo", { method: "POST" });
      if (!response.ok) throw new Error();
      setResult((await response.json()) as SealedDemo);
    } catch {
      setError(true);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Panel
      title="End-to-end encryption, demonstrated"
      caption="A payment agent attaches a card number marked sensitive. It is encrypted to the payment API's key — so the firewall scores the call without ever being able to read that field."
      action={
        <Button variant="primary" size="sm" onClick={() => void run()} disabled={running}>
          {running ? "Sending…" : "Send a sealed call"}
        </Button>
      }
    >
      <div className="px-4 py-4 sm:px-5">
        {error ? (
          <p className="text-[12.5px] text-[var(--block)]">
            The demo did not complete. Try again.
          </p>
        ) : running ? (
          <LoadingRegion label="Sending a sealed call">
            <div className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <Skeleton width="100%" height={94} style={{ borderRadius: 8 }} />
                <Skeleton width="100%" height={94} style={{ borderRadius: 8 }} />
              </div>
              <Skeleton width="100%" height={46} style={{ borderRadius: 8 }} />
            </div>
          </LoadingRegion>
        ) : !result ? (
          <p className="text-[12.5px] leading-relaxed text-[var(--text-muted)]">
            Press the button and the firewall will receive a call containing one
            encrypted field. You will see the ciphertext it holds, the descriptor it
            scored instead of the value, and the verdict it reached.
          </p>
        ) : (
          <div className="space-y-3.5">
            <div className="grid gap-3 sm:grid-cols-2">
              <div
                className="rounded-[var(--r)] border px-3.5 py-3"
                style={{ borderColor: "var(--seal-line)", background: "var(--seal-soft)" }}
              >
                <div
                  className="text-[10px] font-semibold uppercase tracking-[0.06em]"
                  style={{ color: "var(--seal)" }}
                >
                  What the firewall holds
                </div>
                <p className="mono mt-1.5 break-all text-[10.5px] leading-relaxed">
                  {result.ciphertextPreview}
                </p>
                <p className="mt-2 text-[11px] leading-relaxed text-[var(--text-muted)]">
                  Encrypted to the destination. No key in this process opens it.
                </p>
              </div>

              <div className="rounded-[var(--r)] border border-[var(--border)] bg-[var(--bg-inset)] px-3.5 py-3">
                <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-[var(--text-faint)]">
                  What it scored instead
                </div>
                <dl className="mono mt-1.5 space-y-1 text-[11px]">
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--text-muted)]">size</dt>
                    <dd className="tnum">{result.descriptor.bytes} bytes</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--text-muted)]">entropy</dt>
                    <dd className="tnum">{result.descriptor.entropy.toFixed(2)} / 8</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-[var(--text-muted)]">shape</dt>
                    <dd>{result.descriptor.shape}</dd>
                  </div>
                </dl>
                <p className="mt-2 text-[11px] leading-relaxed text-[var(--text-muted)]">
                  Verified against the ciphertext length, so a lying descriptor is
                  caught rather than trusted.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 rounded-[var(--r)] border border-[var(--border)] px-3.5 py-3">
              <VerdictBadge verdict={result.decision.verdict} animate />
              <p className="min-w-0 flex-1 text-[12px] leading-relaxed text-[var(--text-muted)]">
                {result.decision.explanation}
              </p>
            </div>

            <div className="mono grid gap-1 text-[10.5px] text-[var(--text-faint)]">
              <div className="break-all">
                capability root {result.capabilityRoot.slice(0, 32)}…
              </div>
              <div className="break-all">
                request digest {result.requestDigest.slice(0, 32)}…
              </div>
              <div>
                Merkle path length {result.capabilityProofLength} — the firewall
                learned one capability, not the agent&rsquo;s whole grant set.
              </div>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}
