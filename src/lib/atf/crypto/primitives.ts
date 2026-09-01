/**
 * Shared low-level helpers. Everything here is deterministic, dependency-light
 * and safe to run in both the Node runtime and a test process.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

export const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("non-hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

export const random = (n: number): Uint8Array => randomBytes(n);

/** Domain-separated hash. Every call site passes a distinct tag so a digest from
 *  one protocol step can never be replayed as a digest for another. */
export function tagged(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagBytes = utf8(tag);
  let total = tagBytes.length + 1;
  for (const p of parts) total += 4 + p.length;
  const buf = new Uint8Array(total);
  let o = 0;
  buf.set(tagBytes, o);
  o += tagBytes.length;
  buf[o++] = 0x00;
  for (const p of parts) {
    // length-prefix each part so concatenation is unambiguous
    buf[o] = (p.length >>> 24) & 0xff;
    buf[o + 1] = (p.length >>> 16) & 0xff;
    buf[o + 2] = (p.length >>> 8) & 0xff;
    buf[o + 3] = p.length & 0xff;
    o += 4;
    buf.set(p, o);
    o += p.length;
  }
  return sha256(buf);
}

/** Constant-time comparison. Used on every verification path. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Canonical JSON: sorted keys, no whitespace. Two structurally equal objects
 *  always produce the same digest, so signatures bind to meaning not formatting. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
}

export const digestOf = (value: unknown): string =>
  bytesToHex(tagged("atf/digest/v1", utf8(canonicalize(value))));
