"use client";

import { useCallback, useEffect, useState } from "react";
import { Button, Panel, relativeTime } from "@/components/ui";
import { CopyValue } from "@/components/CopyValue";
import {
  verifyCheckpointSignature,
  type Checkpoint,
} from "@/lib/atf/audit/checkpoint";

type Status =
  | { status: "checking" }
  | { status: "consistent"; checkedThrough: number }
  | { status: "rewritten"; seq: number; reason: string }
  | { status: "broken"; seq: number; reason: string }
  | { status: "unavailable"; reason: string }
  | { status: "error" };

const STORAGE_KEY = "atf.checkpoints.v1";
const MAX_SAVED = 10;

function readSaved(): Checkpoint[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? (parsed as Checkpoint[]).slice(0, MAX_SAVED) : [];
  } catch {
    return [];
  }
}

function writeSaved(list: Checkpoint[]): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch {
    // Storage blocked: the checkpoint still shows for this visit and can be downloaded.
  }
}

const TONE: Record<Exclude<Status["status"], "checking">, { label: string; color: string }> = {
  consistent: { label: "Still matches", color: "var(--allow)" },
  rewritten: { label: "History was rewritten", color: "var(--block)" },
  broken: { label: "Log is broken after this point", color: "var(--block)" },
  unavailable: { label: "Can't be checked here", color: "var(--flag)" },
  error: { label: "Check failed — try again", color: "var(--flag)" },
};

/**
 * Checkpoints, explained for someone who has never heard of a hash chain.
 *
 * The chain catches a single edited record, but whoever runs the database could
 * rewrite all of it. A fingerprint saved by someone else, before the rewrite,
 * is what catches that.
 */
export function CheckpointPanel() {
  const [saved, setSaved] = useState<Checkpoint[]>([]);
  const [statuses, setStatuses] = useState<Record<string, Status>>({});
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const check = useCallback(async (checkpoint: Checkpoint) => {
    const key = checkpoint.signature;
    setStatuses((s) => ({ ...s, [key]: { status: "checking" } }));
    try {
      const response = await fetch(
        `/api/audit/verify?seq=${checkpoint.seq}&hash=${checkpoint.hash}`,
        { cache: "no-store" },
      );
      if (!response.ok) throw new Error();
      const data = (await response.json()) as { checkpoint: Status };
      setStatuses((s) => ({ ...s, [key]: data.checkpoint }));
    } catch {
      setStatuses((s) => ({ ...s, [key]: { status: "error" } }));
    }
  }, []);

  useEffect(() => {
    const list = readSaved();
    const first = setTimeout(() => {
      setSaved(list);
      setNow(Date.now());
      for (const checkpoint of list) void check(checkpoint);
    }, 0);
    return () => clearTimeout(first);
  }, [check]);

  const save = async () => {
    setBusy(true);
    setFailed(false);
    try {
      const response = await fetch("/api/audit/checkpoint", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const checkpoint = (await response.json()) as Checkpoint;
      const next = [checkpoint, ...saved.filter((c) => c.signature !== checkpoint.signature)].slice(
        0,
        MAX_SAVED,
      );
      setSaved(next);
      writeSaved(next);
      setNow(Date.now());
      setStatuses((s) => ({
        ...s,
        [checkpoint.signature]: { status: "consistent", checkedThrough: checkpoint.seq },
      }));
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  const remove = (signature: string) => {
    const next = saved.filter((c) => c.signature !== signature);
    setSaved(next);
    writeSaved(next);
  };

  const download = (checkpoint: Checkpoint) => {
    const blob = new Blob([JSON.stringify(checkpoint, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `atf-checkpoint-${checkpoint.seq}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Panel
      title="Save a fingerprint of the log"
      caption="The check above catches one edited record. But whoever runs the server could rewrite the whole log. A fingerprint you save now stops matching if that ever happens — even if every hash was recomputed."
      action={
        <Button variant="secondary" size="sm" onClick={() => void save()} disabled={busy}>
          {busy ? "Saving…" : "Save fingerprint"}
        </Button>
      }
    >
      <div className="px-4 py-4 sm:px-5">
        {failed ? (
          <p className="mb-3 text-[12.5px] text-[var(--block)]">
            Could not get a fingerprint from the server. Try again.
          </p>
        ) : null}

        {saved.length === 0 ? (
          <p className="text-[12.5px] leading-relaxed text-[var(--text-muted)]">
            No fingerprints saved in this browser yet. Save one, come back later, and this
            page re-checks it automatically. Download it to keep a copy somewhere the
            server&rsquo;s operator cannot reach.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--border)]">
            {saved.map((checkpoint) => {
              const state = statuses[checkpoint.signature] ?? { status: "checking" as const };
              const tone = state.status === "checking" ? null : TONE[state.status];
              const signed = verifyCheckpointSignature(checkpoint);
              return (
                <li
                  key={checkpoint.signature}
                  className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                      <span className="font-medium">Record {checkpoint.seq}</span>
                      <span className="text-[var(--text-faint)]">
                        saved {relativeTime(checkpoint.issuedAt, now)}
                      </span>
                      <span
                        className="inline-flex items-center gap-1.5 font-medium"
                        style={{ color: tone?.color ?? "var(--text-muted)" }}
                        aria-live="polite"
                      >
                        <span
                          aria-hidden="true"
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: tone?.color ?? "var(--text-faint)" }}
                        />
                        {tone?.label ?? "Checking…"}
                      </span>
                    </div>
                    <div className="mono mt-1 text-[10.5px] text-[var(--text-muted)]">
                      <CopyValue
                        value={checkpoint.hash}
                        display={`${checkpoint.hash.slice(0, 24)}…`}
                        title="checkpoint hash"
                      />
                      <span className="ml-2 text-[var(--text-faint)]">
                        {signed ? "signed by this server" : "signature does not verify"}
                      </span>
                    </div>
                    {state.status === "rewritten" ||
                    state.status === "broken" ||
                    state.status === "unavailable" ? (
                      <p className="mt-1 text-[11.5px] text-[var(--text-muted)]">{state.reason}</p>
                    ) : null}
                  </div>
                  <div className="flex gap-1.5">
                    <Button variant="ghost" size="sm" onClick={() => void check(checkpoint)}>
                      Re-check
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => download(checkpoint)}>
                      Download
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => remove(checkpoint.signature)}
                      ariaLabel={`Forget the fingerprint of record ${checkpoint.seq}`}
                    >
                      Forget
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}
