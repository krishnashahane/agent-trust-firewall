/**
 * End-to-end encrypted envelopes.
 *
 *   X25519 ECDH  ->  HKDF-SHA256  ->  XChaCha20-Poly1305 AEAD
 *
 * The sender generates a fresh ephemeral keypair for every envelope, so
 * compromising a long-term key later does not decrypt traffic captured earlier
 * (forward secrecy). The envelope's metadata — sender identity and the digest of
 * the request it carries — is bound in as AEAD associated data: an attacker who
 * moves a ciphertext onto a different request or a different agent id gets an
 * authentication failure, not a decryption.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytesToHex,
  canonicalize,
  fromUtf8,
  hexToBytes,
  random,
  utf8,
} from "./primitives.ts";

export interface EncryptionKeyPair {
  secretKey: string;
  publicKey: string;
}

export interface SealedEnvelope {
  /** protocol version — refuse anything we do not recognise */
  v: 1;
  /** ephemeral X25519 public key, hex */
  epk: string;
  /** 24-byte nonce, hex */
  nonce: string;
  /** ciphertext||tag, hex */
  ct: string;
  /** associated data, authenticated but not encrypted */
  aad: EnvelopeAad;
}

export interface EnvelopeAad {
  agentId: string;
  requestDigest: string;
  /** epoch ms — receivers reject envelopes outside their freshness window */
  issuedAt: number;
}

const MAX_PLAINTEXT_BYTES = 256 * 1024;

export function generateEncryptionKeyPair(): EncryptionKeyPair {
  const secretKey = x25519.utils.randomPrivateKey();
  return {
    secretKey: bytesToHex(secretKey),
    publicKey: bytesToHex(x25519.getPublicKey(secretKey)),
  };
}

export const encryptionPublicKeyFor = (secretKey: string): string =>
  bytesToHex(x25519.getPublicKey(hexToBytes(secretKey)));

/** Both sides derive the same key from the same transcript, so a mismatched
 *  transcript (different epk, recipient, or aad) simply fails to open. */
function deriveKey(
  shared: Uint8Array,
  ephemeralPublic: string,
  recipientPublic: string,
  aad: EnvelopeAad,
): Uint8Array {
  return hkdf(
    sha256,
    shared,
    utf8("atf/e2ee/salt/v1"),
    utf8(`atf/e2ee/v1|${ephemeralPublic}|${recipientPublic}|${canonicalize(aad)}`),
    32,
  );
}

export function seal(
  recipientPublicKey: string,
  payload: unknown,
  aad: EnvelopeAad,
): SealedEnvelope {
  const plaintext = utf8(JSON.stringify(payload));
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new Error("payload exceeds envelope limit");
  }
  const ephemeralSecret = x25519.utils.randomPrivateKey();
  const epk = bytesToHex(x25519.getPublicKey(ephemeralSecret));
  const shared = x25519.getSharedSecret(
    ephemeralSecret,
    hexToBytes(recipientPublicKey),
  );
  const key = deriveKey(shared, epk, recipientPublicKey, aad);
  const nonce = random(24);
  const ct = xchacha20poly1305(key, nonce, utf8(canonicalize(aad))).encrypt(plaintext);

  return { v: 1, epk, nonce: bytesToHex(nonce), ct: bytesToHex(ct), aad };
}

export class EnvelopeError extends Error {}

/**
 * Open an envelope. Every failure — wrong key, tampered ciphertext, altered
 * associated data, stale timestamp — raises the same opaque error, so a probing
 * caller cannot use the error text as a decryption oracle.
 */
export function open<T = unknown>(
  recipientSecretKey: string,
  envelope: SealedEnvelope,
  opts: { maxAgeMs?: number; now?: number } = {},
): T {
  const maxAgeMs = opts.maxAgeMs ?? 120_000;
  const now = opts.now ?? Date.now();
  try {
    if (envelope.v !== 1) throw new Error("version");
    const skew = now - envelope.aad.issuedAt;
    if (!Number.isFinite(skew) || skew > maxAgeMs || skew < -30_000) {
      throw new Error("freshness");
    }
    const recipientPublic = encryptionPublicKeyFor(recipientSecretKey);
    const shared = x25519.getSharedSecret(
      hexToBytes(recipientSecretKey),
      hexToBytes(envelope.epk),
    );
    const key = deriveKey(shared, envelope.epk, recipientPublic, envelope.aad);
    const plaintext = xchacha20poly1305(
      key,
      hexToBytes(envelope.nonce),
      utf8(canonicalize(envelope.aad)),
    ).decrypt(hexToBytes(envelope.ct));
    return JSON.parse(fromUtf8(plaintext)) as T;
  } catch {
    throw new EnvelopeError("envelope could not be opened");
  }
}
