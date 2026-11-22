import { describe, expect, it } from "vitest";
import {
  generateKeyPair,
  isValidPublicKey,
  prove,
  publicKeyFor,
  verify,
} from "@/lib/atf/identity/schnorr";
import {
  capabilityRoot,
  normalizeCapabilities,
  proveCapability,
  verifyCapability,
} from "@/lib/atf/identity/merkle";
import {
  EnvelopeError,
  generateEncryptionKeyPair,
  open,
  seal,
} from "@/lib/atf/crypto/e2ee";
import {
  canonicalize,
  digestOf,
  hexToBytes,
  timingSafeEqual,
  bytesToHex,
} from "@/lib/atf/crypto/primitives";
import {
  describe as describeField,
  openField,
  sealField,
  shannonEntropy,
  verifySealedField,
} from "@/lib/atf/crypto/sealed";

describe("primitives", () => {
  it("canonicalises objects independently of key order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(digestOf({ x: [1, 2] })).toBe(digestOf({ x: [1, 2] }));
    expect(digestOf({ x: [1, 2] })).not.toBe(digestOf({ x: [2, 1] }));
  });

  it("length-prefixes hash inputs so concatenations are unambiguous", () => {
    // Without length prefixing, ("ab","c") and ("a","bc") would collide.
    expect(digestOf(["ab", "c"])).not.toBe(digestOf(["a", "bc"]));
  });

  it("rejects malformed hex rather than silently truncating", () => {
    expect(() => hexToBytes("zz")).toThrow();
    expect(() => hexToBytes("abc")).toThrow();
    expect(bytesToHex(hexToBytes("00ff"))).toBe("00ff");
  });

  it("compares in constant time and still compares correctly", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});

describe("schnorr zero-knowledge proofs", () => {
  const keys = generateKeyPair();
  const nonce = "a".repeat(64);
  const digest = digestOf({ tool: "payments.charge" });

  it("verifies an honest proof", () => {
    expect(verify(keys.publicKey, prove(keys.secretKey, nonce, digest), nonce, digest)).toBe(
      true,
    );
  });

  it("derives the same public key from the secret", () => {
    expect(publicKeyFor(keys.secretKey)).toBe(keys.publicKey);
  });

  it("never transmits the secret key in the proof", () => {
    const proof = prove(keys.secretKey, nonce, digest);
    const serialized = JSON.stringify(proof);
    expect(serialized).not.toContain(keys.secretKey);
    // Nor any substring long enough to be useful.
    expect(serialized).not.toContain(keys.secretKey.slice(0, 32));
  });

  it("produces a different proof each time (fresh randomness)", () => {
    const a = prove(keys.secretKey, nonce, digest);
    const b = prove(keys.secretKey, nonce, digest);
    expect(a.commitment).not.toBe(b.commitment);
    expect(a.response).not.toBe(b.response);
  });

  it("rejects a proof bound to a different request", () => {
    const proof = prove(keys.secretKey, nonce, digest);
    expect(verify(keys.publicKey, proof, nonce, digestOf({ tool: "other" }))).toBe(false);
  });

  it("rejects a proof bound to a different nonce", () => {
    const proof = prove(keys.secretKey, nonce, digest);
    expect(verify(keys.publicKey, proof, "b".repeat(64), digest)).toBe(false);
  });

  it("rejects a proof checked against another agent's public key", () => {
    const other = generateKeyPair();
    const proof = prove(keys.secretKey, nonce, digest);
    expect(verify(other.publicKey, proof, nonce, digest)).toBe(false);
  });

  it("rejects a tampered response scalar", () => {
    const proof = prove(keys.secretKey, nonce, digest);
    const flipped = (parseInt(proof.response.slice(-1), 16) ^ 1).toString(16);
    expect(
      verify(
        keys.publicKey,
        { ...proof, response: proof.response.slice(0, -1) + flipped },
        nonce,
        digest,
      ),
    ).toBe(false);
  });

  it("returns false rather than throwing on garbage input", () => {
    expect(verify("not-a-key", { commitment: "x", response: "y" }, nonce, digest)).toBe(
      false,
    );
    expect(
      verify(keys.publicKey, { commitment: "", response: "" }, nonce, digest),
    ).toBe(false);
  });

  it("rejects a zero response, which would prove nothing", () => {
    const proof = prove(keys.secretKey, nonce, digest);
    expect(verify(keys.publicKey, { ...proof, response: "0".repeat(64) }, nonce, digest)).toBe(
      false,
    );
  });
});

describe("merkle capability proofs", () => {
  const caps = ["payments:charge", "payments:refund", "calendar:*", "search:query"];
  const root = capabilityRoot(caps);

  it("normalises capabilities so the root is canonical", () => {
    expect(capabilityRoot(caps)).toBe(capabilityRoot([...caps].reverse()));
    expect(normalizeCapabilities([" a ", "a", "b"])).toEqual(["a", "b"]);
  });

  it("proves and verifies each granted capability", () => {
    for (const capability of caps) {
      const proof = proveCapability(caps, capability);
      expect(proof).not.toBeNull();
      expect(verifyCapability(root, proof!)).toBe(true);
    }
  });

  it("cannot prove a capability that was never granted", () => {
    expect(proveCapability(caps, "admin:root")).toBeNull();
  });

  it("rejects a forged proof for an ungranted capability", () => {
    const stolen = proveCapability(caps, "search:query")!;
    expect(verifyCapability(root, { ...stolen, capability: "admin:root" })).toBe(false);
  });

  it("rejects a proof against a different agent's root", () => {
    const proof = proveCapability(caps, "calendar:*")!;
    expect(verifyCapability(capabilityRoot(["other:thing"]), proof)).toBe(false);
  });

  it("rejects a tampered sibling path", () => {
    const proof = proveCapability(caps, "payments:charge")!;
    const tampered = { ...proof, path: proof.path.map(() => "0".repeat(64)) };
    expect(verifyCapability(root, tampered)).toBe(false);
  });

  it("rejects an internal node passed off as a leaf", () => {
    // Domain separation between leaf and node hashes is what prevents this.
    const proof = proveCapability(caps, "calendar:*")!;
    const sibling = proof.path[0]!;
    expect(verifyCapability(root, { capability: sibling, index: 0, path: [] })).toBe(
      false,
    );
  });

  it("bounds path length so a caller cannot force unbounded work", () => {
    const proof = proveCapability(caps, "search:query")!;
    expect(
      verifyCapability(root, { ...proof, path: new Array(64).fill("0".repeat(64)) }),
    ).toBe(false);
  });
});

describe("end-to-end encryption", () => {
  const recipient = generateEncryptionKeyPair();
  const aad = { agentId: "agent-1", requestDigest: "d".repeat(64), issuedAt: Date.now() };

  it("round-trips a payload", () => {
    const envelope = seal(recipient.publicKey, { amount: 42 }, aad);
    expect(open<{ amount: number }>(recipient.secretKey, envelope).amount).toBe(42);
  });

  it("does not leak the plaintext into the envelope", () => {
    const envelope = seal(recipient.publicKey, { secret: "hunter2" }, aad);
    expect(JSON.stringify(envelope)).not.toContain("hunter2");
  });

  it("uses a fresh ephemeral key per envelope (forward secrecy)", () => {
    const a = seal(recipient.publicKey, { x: 1 }, aad);
    const b = seal(recipient.publicKey, { x: 1 }, aad);
    expect(a.epk).not.toBe(b.epk);
    expect(a.ct).not.toBe(b.ct);
  });

  it("refuses the wrong recipient key", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, aad);
    const other = generateEncryptionKeyPair();
    expect(() => open(other.secretKey, envelope)).toThrow(EnvelopeError);
  });

  it("refuses a flipped ciphertext byte", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, aad);
    const flipped = (parseInt(envelope.ct.slice(0, 1), 16) ^ 1).toString(16);
    expect(() =>
      open(recipient.secretKey, { ...envelope, ct: flipped + envelope.ct.slice(1) }),
    ).toThrow(EnvelopeError);
  });

  it("refuses altered associated data — an envelope cannot be re-attributed", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, aad);
    expect(() =>
      open(recipient.secretKey, {
        ...envelope,
        aad: { ...envelope.aad, agentId: "someone-else" },
      }),
    ).toThrow(EnvelopeError);
  });

  it("refuses a stale envelope", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, {
      ...aad,
      issuedAt: Date.now() - 600_000,
    });
    expect(() => open(recipient.secretKey, envelope)).toThrow(EnvelopeError);
  });

  it("refuses an unknown protocol version", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, aad);
    expect(() =>
      open(recipient.secretKey, { ...envelope, v: 2 as unknown as 1 }),
    ).toThrow(EnvelopeError);
  });

  it("reports every failure identically, giving no decryption oracle", () => {
    const envelope = seal(recipient.publicKey, { x: 1 }, aad);
    const other = generateEncryptionKeyPair();
    const messages = new Set<string>();
    try {
      open(other.secretKey, envelope);
    } catch (e) {
      messages.add((e as Error).message);
    }
    try {
      open(recipient.secretKey, { ...envelope, nonce: "0".repeat(48) });
    } catch (e) {
      messages.add((e as Error).message);
    }
    expect(messages.size).toBe(1);
  });
});

describe("sealed fields", () => {
  const destination = generateEncryptionKeyPair();
  const aad = { agentId: "a", requestDigest: "e".repeat(64), issuedAt: Date.now() };

  it("keeps the value unreadable without the destination key", () => {
    const field = sealField(destination.publicKey, "4242424242424242", aad);
    expect(JSON.stringify(field)).not.toContain("4242424242424242");
    expect(openField(destination.secretKey, field)).toBe("4242424242424242");
  });

  it("accepts an honest descriptor", () => {
    const field = sealField(destination.publicKey, "hello world", aad);
    const checked = verifySealedField(field);
    expect(checked.trustworthy).toBe(true);
    expect(checked.descriptor.bytes).toBe(11);
  });

  it("catches a descriptor that lies about its size", () => {
    const field = sealField(destination.publicKey, "x".repeat(500), aad);
    const lying = { ...field, descriptor: { ...field.descriptor, bytes: 4 } };
    const checked = verifySealedField(lying);
    expect(checked.trustworthy).toBe(false);
    // An unverifiable field is scored as maximally suspicious, not trusted.
    expect(checked.descriptor.entropy).toBe(8);
  });

  it("measures entropy and shape sensibly", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("abcd")).toBeGreaterThan(1.9);
    expect(describeField("hello@example.com").shape).toBe("identifier");
    expect(describeField('{"a":1}').shape).toBe("structured");
  });
});

describe("enrolment key validation", () => {
  it("accepts a freshly generated public key", () => {
    expect(isValidPublicKey(generateKeyPair().publicKey)).toBe(true);
  });

  it("refuses the identity point, small-order points and garbage", () => {
    const identity = "01" + "00".repeat(31);
    expect(isValidPublicKey(identity)).toBe(false);
    expect(isValidPublicKey("00".repeat(32))).toBe(false);
    expect(isValidPublicKey("ff".repeat(32))).toBe(false);
    expect(isValidPublicKey("not hex")).toBe(false);
  });
});
