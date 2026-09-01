/**
 * Turning raw arguments into something the risk engine can score.
 *
 * Sealed fields are the interesting case: ATF cannot read them, so it scores
 * their verified descriptors instead of their values, and treats a descriptor
 * that does not match its own ciphertext as a lie rather than as data.
 *
 * Traversal is depth- and size-bounded. Argument objects arrive from untrusted
 * agents, and an unbounded walk over attacker-controlled nesting is a denial of
 * service waiting to happen.
 */
import { describe, isSealedField, verifySealedField } from "../crypto/sealed.ts";
import type { ArgumentSummary } from "../types.ts";

const MAX_DEPTH = 8;
const MAX_TEXT = 64_000;
const MAX_CHILDREN = 256;

export interface ArgumentAnalysis extends ArgumentSummary {
  /** concatenated readable values, for the payload scanner */
  inspectableText: string;
}

export function summarizeArguments(args: Record<string, unknown>): ArgumentAnalysis {
  let fieldCount = 0;
  let totalBytes = 0;
  let sealedFieldCount = 0;
  let maxEntropy = 0;
  let descriptorMismatch = false;
  const texts: string[] = [];
  let textLength = 0;

  const collect = (text: string): void => {
    if (textLength >= MAX_TEXT) return;
    const slice = text.slice(0, MAX_TEXT - textLength);
    texts.push(slice);
    textLength += slice.length;
  };

  const walk = (value: unknown, depth: number): void => {
    if (depth > MAX_DEPTH) return;

    if (isSealedField(value)) {
      sealedFieldCount++;
      fieldCount++;
      const { trustworthy, descriptor } = verifySealedField(value);
      if (!trustworthy) descriptorMismatch = true;
      totalBytes += descriptor.bytes;
      maxEntropy = Math.max(maxEntropy, descriptor.entropy);
      return;
    }

    if (typeof value === "string") {
      fieldCount++;
      const d = describe(value);
      totalBytes += d.bytes;
      maxEntropy = Math.max(maxEntropy, d.entropy);
      collect(value);
      return;
    }

    if (typeof value === "number" || typeof value === "boolean" || value === null) {
      fieldCount++;
      totalBytes += String(value).length;
      return;
    }

    if (Array.isArray(value)) {
      for (const item of value.slice(0, MAX_CHILDREN)) walk(item, depth + 1);
      return;
    }

    if (typeof value === "object") {
      const entries = Object.entries(value as Record<string, unknown>).slice(0, MAX_CHILDREN);
      for (const [key, child] of entries) {
        // keys are attacker-controlled text too, and worth scanning
        collect(key);
        walk(child, depth + 1);
      }
    }
  };

  walk(args, 0);

  return {
    fieldCount,
    totalBytes,
    sealedFieldCount,
    maxEntropy,
    descriptorMismatch,
    // Sliced again after joining: the separators themselves count toward the
    // bound, so the guarantee holds exactly rather than approximately.
    inspectableText: texts.join(" \n ").slice(0, MAX_TEXT),
  };
}
