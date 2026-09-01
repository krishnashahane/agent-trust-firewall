/**
 * Payload inspection.
 *
 * Two distinct dangers live in agent arguments. The first is prompt injection —
 * text engineered to hijack a downstream model's instructions. The second is
 * exfiltration — credentials or bulk high-entropy data riding out inside an
 * ordinary-looking call.
 *
 * These are heuristics and are treated as such: they raise a score, they never
 * decide alone. Matching is done on a length-capped copy so a huge payload
 * cannot be used to burn CPU.
 */
import type { RequestContext, SignalResult } from "../../types.ts";

const SCAN_LIMIT = 32_000;

const INJECTION_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i, label: "instruction override" },
  { re: /disregard\s+(your|all|the)\s+(rules|instructions|guidelines)/i, label: "instruction override" },
  { re: /you\s+are\s+now\s+(a|an|in)\s+/i, label: "role reassignment" },
  { re: /\bsystem\s*(prompt|message)\s*[:=]/i, label: "system-prompt injection" },
  { re: /<\/?(system|instructions?)>/i, label: "prompt tag injection" },
  { re: /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)/i, label: "prompt extraction" },
  { re: /developer\s+mode|jailbreak|DAN\s+mode/i, label: "jailbreak phrasing" },
];

const SECRET_PATTERNS: { re: RegExp; label: string }[] = [
  // Real key formats carry hyphens and underscores (sk-proj-…, sk-live-…),
  // so a strictly alphanumeric pattern misses most of them.
  { re: /\bsk-[A-Za-z0-9_-]{16,}\b/, label: "API key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS access key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, label: "GitHub token" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, label: "Slack token" },
  { re: /\bAIza[0-9A-Za-z_-]{30,}\b/, label: "Google API key" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: "private key" },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, label: "JWT" },
  { re: /\b(?:\d[ -]?){13,19}\b/, label: "card-like number" },
];

export function payloadSignal(ctx: RequestContext): SignalResult {
  const text = ctx.inspectableText.slice(0, SCAN_LIMIT);

  const injections = INJECTION_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
  const secrets = SECRET_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);

  // High entropy in a field that claims to be ordinary text is how encoded
  // payloads look. Sealed fields contribute their descriptor, not their value.
  const entropy = ctx.argumentSummary.maxEntropy;
  const entropyScore = entropy > 5.5 ? Math.min(1, (entropy - 5.5) / 2) : 0;

  const score = Math.min(
    1,
    (injections.length > 0 ? 0.85 : 0) +
      (secrets.length > 0 ? 0.75 : 0) +
      entropyScore * 0.3 +
      (ctx.argumentSummary.descriptorMismatch ? 0.6 : 0),
  );

  const notes: string[] = [];
  if (injections.length > 0) {
    notes.push(`text that looks like prompt injection (${[...new Set(injections)].join(", ")})`);
  }
  if (secrets.length > 0) {
    notes.push(`what appears to be a secret in the arguments (${[...new Set(secrets)].join(", ")})`);
  }
  if (entropyScore > 0.3) notes.push("unusually random-looking data for this kind of field");
  if (ctx.argumentSummary.descriptorMismatch) {
    notes.push("an encrypted field whose declared size does not match its ciphertext");
  }

  return {
    id: "payload",
    label: "Payload inspection",
    score,
    evidence:
      notes.length === 0
        ? "Nothing suspicious in the arguments ATF is permitted to read."
        : `The arguments contain ${notes.join(", and ")}.`,
  };
}
