/**
 * Proof of secret-key possession.
 *
 * Plainly: this is a Schnorr signature over (nonce, requestDigest). Phrased as
 * a Fiat–Shamir proof of knowledge it is zero-knowledge about the key, which is
 * the property that matters — but it is not a privacy-preserving credential and
 * the firewall knows exactly which agent is calling. See ADR 0001.
 *
 * A non-interactive Schnorr proof (Fiat-Shamir) over ed25519's prime-order group.
 * The agent proves it knows the scalar `x` behind its public point `P = x*G`
 * without ever transmitting `x`. The Fiat-Shamir challenge commits to the
 * gateway-issued nonce AND the digest of the specific request being made, so a
 * captured proof is worthless for any other call: it is bound to one request.
 *
 *   prove:   r <- random scalar;  R = r*G;  c = H(P, R, nonce, requestDigest);  s = r + c*x
 *   verify:  s*G  ==  R + c*P
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, random, tagged, utf8 } from "../crypto/primitives.ts";

const Point = ed25519.Point;
const ORDER = Point.Fn.ORDER;

export interface KeyPair {
  /** hex-encoded scalar — never leaves the agent */
  secretKey: string;
  /** hex-encoded compressed point */
  publicKey: string;
}

export interface SchnorrProof {
  /** commitment R, hex-encoded compressed point */
  commitment: string;
  /** response s, hex-encoded 32-byte big-endian scalar */
  response: string;
}

const scalarToHex = (n: bigint): string => n.toString(16).padStart(64, "0");

function randomScalar(): bigint {
  // Rejection-free reduction with wide input keeps the bias negligible.
  const wide = BigInt("0x" + bytesToHex(random(64)));
  return (wide % (ORDER - 1n)) + 1n;
}

export function generateKeyPair(): KeyPair {
  const x = randomScalar();
  return {
    secretKey: scalarToHex(x),
    publicKey: Point.BASE.multiply(x).toHex(),
  };
}

/**
 * A key the firewall can safely enrol: a canonical encoding of a point in the
 * prime-order subgroup. Small-order points (including the identity) are
 * refused — a proof against one says nothing about who holds a secret.
 */
export function isValidPublicKey(hex: string): boolean {
  try {
    const P = Point.fromHex(hex);
    return !P.isSmallOrder() && P.isTorsionFree() && P.toHex() === hex.toLowerCase();
  } catch {
    return false;
  }
}

export function publicKeyFor(secretKey: string): string {
  return Point.BASE.multiply(parseScalar(secretKey)).toHex();
}

function parseScalar(hex: string): bigint {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) throw new Error("scalar must be 32 bytes");
  const n = BigInt("0x" + hex) % ORDER;
  if (n === 0n) throw new Error("scalar must be non-zero");
  return n;
}

function challenge(
  publicKey: string,
  commitment: string,
  nonce: string,
  requestDigest: string,
): bigint {
  const h = tagged(
    "atf/schnorr-challenge/v1",
    hexToBytes(publicKey),
    hexToBytes(commitment),
    utf8(nonce),
    utf8(requestDigest),
  );
  return BigInt("0x" + bytesToHex(h)) % ORDER;
}

export function prove(
  secretKey: string,
  nonce: string,
  requestDigest: string,
): SchnorrProof {
  const x = parseScalar(secretKey);
  const publicKey = Point.BASE.multiply(x).toHex();
  const r = randomScalar();
  const commitment = Point.BASE.multiply(r).toHex();
  const c = challenge(publicKey, commitment, nonce, requestDigest);
  const s = (r + c * x) % ORDER;
  return { commitment, response: scalarToHex(s) };
}

/**
 * Verify a proof. Returns false — never throws — on any malformed input, so a
 * hostile agent cannot turn a parse error into a different code path.
 */
export function verify(
  publicKey: string,
  proof: SchnorrProof,
  nonce: string,
  requestDigest: string,
): boolean {
  try {
    const P = Point.fromHex(publicKey);
    const R = Point.fromHex(proof.commitment);
    const s = BigInt("0x" + proof.response);
    if (s <= 0n || s >= ORDER) return false;
    if (hexToBytes(proof.response).length !== 32) return false;

    const c = challenge(publicKey, proof.commitment, nonce, requestDigest);
    const lhs = Point.BASE.multiply(s);
    const rhs = R.add(P.multiply(c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
