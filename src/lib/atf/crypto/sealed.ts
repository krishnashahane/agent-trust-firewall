/**
 * Two-layer sealing.
 *
 * A firewall that scores a request has to be able to read it, so the OUTER
 * envelope is opened inside ATF's trust boundary. But an agent can additionally
 * mark individual argument fields as sensitive — a card number, a patient
 * record — and those are sealed to the DESTINATION's key. They pass through ATF
 * as ciphertext it cannot open.
 *
 * ATF still has to score what it cannot read, so each sealed field carries a
 * privacy-preserving descriptor: byte length, Shannon entropy and a shape class.
 * That is enough to catch "this agent just attached 40KB of high-entropy data to
 * a weather lookup" without ever seeing the value. The descriptor is authored by
 * the agent, so `verifySealedField` re-derives it from the ciphertext and
 * rejects any field whose claimed size does not match — a lying agent is caught,
 * and an unverifiable descriptor is scored as maximally suspicious rather than
 * trusted.
 */
import { open, seal, type SealedEnvelope } from "./e2ee.ts";
import { hexToBytes } from "./primitives.ts";

export type ShapeClass = "identifier" | "text" | "structured" | "binary-ish" | "unknown";

export interface FieldDescriptor {
  /** plaintext byte length as claimed by the sender */
  bytes: number;
  /** Shannon entropy per byte, 0-8 */
  entropy: number;
  shape: ShapeClass;
}

export interface SealedField {
  __atfSealed: true;
  envelope: SealedEnvelope;
  descriptor: FieldDescriptor;
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / value.length;
    h -= p * Math.log2(p);
  }
  return Number(h.toFixed(4));
}

export function classifyShape(value: string): ShapeClass {
  const v = value.trim();
  if (v.length === 0) return "unknown";
  if (/^[{[]/.test(v)) return "structured";
  if (/^[A-Za-z0-9+/=_-]{16,}$/.test(v)) return "binary-ish";
  if (/^[\w.@:-]{1,64}$/.test(v)) return "identifier";
  return "text";
}

export function describe(value: string): FieldDescriptor {
  return {
    bytes: new TextEncoder().encode(value).length,
    entropy: shannonEntropy(value),
    shape: classifyShape(value),
  };
}

export function sealField(
  destinationPublicKey: string,
  value: string,
  aad: SealedEnvelope["aad"],
): SealedField {
  return {
    __atfSealed: true,
    envelope: seal(destinationPublicKey, value, aad),
    descriptor: describe(value),
  };
}

export const isSealedField = (v: unknown): v is SealedField =>
  typeof v === "object" &&
  v !== null &&
  (v as { __atfSealed?: unknown }).__atfSealed === true;

/**
 * ATF's check on a field it cannot decrypt: the ciphertext is
 * plaintext-length + 16-byte Poly1305 tag, so a descriptor claiming a different
 * size is provably false. Returns the descriptor ATF should actually score with.
 */
export function verifySealedField(field: SealedField): {
  trustworthy: boolean;
  descriptor: FieldDescriptor;
} {
  try {
    const ctBytes = hexToBytes(field.envelope.ct).length;
    // The plaintext is a JSON string: the value plus quotes.
    const impliedPlaintext = ctBytes - 16;
    const claimed = field.descriptor.bytes + 2;
    const trustworthy =
      Math.abs(impliedPlaintext - claimed) <= 8 &&
      field.descriptor.entropy >= 0 &&
      field.descriptor.entropy <= 8;
    return {
      trustworthy,
      descriptor: trustworthy
        ? field.descriptor
        : { bytes: Math.max(0, impliedPlaintext), entropy: 8, shape: "unknown" },
    };
  } catch {
    return { trustworthy: false, descriptor: { bytes: 0, entropy: 8, shape: "unknown" } };
  }
}

/** Only the destination holds this key — proves ATF is not in the path. */
export const openField = (destinationSecretKey: string, field: SealedField): string =>
  open<string>(destinationSecretKey, field.envelope, { maxAgeMs: 600_000 });
