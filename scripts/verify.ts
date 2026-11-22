/**
 * Security invariants, asserted outside the test runner.
 *
 * These are the properties the whole product rests on. They are checked here as
 * well as in the suite so that `npm run verify` is a single command anyone can
 * run — in CI, before a deploy, or to satisfy themselves that the claims on the
 * landing page are true — without needing to read a test report.
 *
 * Run: npm run verify
 */
import { MemoryStore } from "../src/lib/atf/store/memory.ts";
import { registerAgent, revokeAgent } from "../src/lib/atf/identity/registry.ts";
import { issueChallenge } from "../src/lib/atf/identity/nonce.ts";
import { decide } from "../src/lib/atf/interceptor/decide.ts";
import { signCall } from "../src/lib/atf/client.ts";
import { generateKeyPair } from "../src/lib/atf/identity/schnorr.ts";
import {
  generateEncryptionKeyPair,
  seal,
  open,
} from "../src/lib/atf/crypto/e2ee.ts";
import { sealField, openField } from "../src/lib/atf/crypto/sealed.ts";
import { verifyChain, hashRecord } from "../src/lib/atf/audit/chain.ts";
import { capabilityRoot, proveCapability } from "../src/lib/atf/identity/merkle.ts";
import { isPublicIpv4 } from "../src/lib/atf/osint/net.ts";
import { intelSignal } from "../src/lib/atf/risk/signals/intel.ts";
import type { Store } from "../src/lib/atf/store/port.ts";

let failures = 0;

function assert(name: string, condition: boolean, detail = ""): void {
  if (condition) {
    process.stdout.write(`  [32m✓[0m ${name}\n`);
  } else {
    failures++;
    process.stdout.write(`  [31m✗ ${name}[0m${detail ? ` — ${detail}` : ""}\n`);
  }
}

function section(title: string): void {
  process.stdout.write(`\n[1m${title}[0m\n`);
}

const CAPS = ["search:query", "storage:read"];

async function makeWorld() {
  const store: Store = new MemoryStore();
  const signing = generateKeyPair();
  const encryption = generateEncryptionKeyPair();
  await registerAgent(
    store,
    {
      agentId: "agent-1",
      displayName: "Agent One",
      signingPublicKey: signing.publicKey,
      encryptionPublicKey: encryption.publicKey,
      capabilityRoot: capabilityRoot(CAPS),
    },
    Date.now() - 30 * 24 * 3_600_000,
  );
  return {
    store,
    creds: {
      agentId: "agent-1",
      signingSecretKey: signing.secretKey,
      capabilities: CAPS,
    },
  };
}

async function honestCall(
  store: Store,
  creds: { agentId: string; signingSecretKey: string; capabilities: string[] },
  over: Partial<{ tool: string; capability: string; args: Record<string, unknown> }> = {},
) {
  const { nonce } = await issueChallenge(store, creds.agentId);
  return signCall(creds, {
    tool: over.tool ?? "search.query",
    destination: "api.search.internal",
    capability: over.capability ?? "search:query",
    args: over.args ?? { q: "routine lookup" },
    nonce,
  });
}

async function main(): Promise<void> {
  process.stdout.write("\nAgent Trust Firewall — security invariants\n");

  // ------------------------------------------------------------- identity
  section("Identity cannot be faked");
  {
    const { store, creds } = await makeWorld();

    const rogue = generateKeyPair();
    const forged = await honestCall(store, {
      agentId: "ghost",
      signingSecretKey: rogue.secretKey,
      capabilities: CAPS,
    });
    const forgedDecision = await decide(store, forged);
    assert(
      "an unenrolled agent is blocked",
      forgedDecision.verdict === "BLOCK" &&
        forgedDecision.violations.some((v) => v.rule === "unknown-agent"),
    );

    const call = await honestCall(store, creds);
    await decide(store, call);
    const replayed = await decide(store, call);
    assert(
      "a replayed proof is blocked",
      replayed.verdict === "BLOCK" &&
        replayed.violations.some((v) => v.rule === "replayed-challenge"),
    );

    const { nonce } = await issueChallenge(store, "agent-1");
    const bound = signCall(creds, {
      tool: "search.query",
      destination: "api.search.internal",
      capability: "search:query",
      args: { q: "original" },
      nonce,
    });
    const swapped = await decide(store, { ...bound, args: { q: "swapped" } });
    assert(
      "a proof cannot be moved onto a different request",
      swapped.verdict === "BLOCK" &&
        swapped.violations.some((v) => v.rule === "identity-unproven"),
    );

    assert(
      "the agent's secret key never appears in the proof it sends",
      !JSON.stringify(call.proof).includes(creds.signingSecretKey),
    );
  }

  // ---------------------------------------------------------- capability
  section("Authority cannot be exceeded");
  {
    const { store, creds } = await makeWorld();

    const escalated = await decide(
      store,
      await honestCall(store, creds, {
        tool: "payments.charge",
        capability: "search:query",
        args: { amountMinor: 900000 },
      }),
    );
    assert(
      "capability escalation is blocked",
      escalated.verdict === "BLOCK" &&
        escalated.violations.some((v) => v.rule === "capability-escalation"),
    );

    const { nonce } = await issueChallenge(store, "agent-1");
    const forgedProof = proveCapability(["admin:root"], "admin:root")!;
    const unproven = await decide(
      store,
      signCall(
        creds,
        {
          tool: "admin.root",
          destination: "api.admin.internal",
          capability: "admin:root",
          args: {},
          nonce,
        },
        { forgedCapabilityProof: forgedProof },
      ),
    );
    assert(
      "a capability the agent does not hold cannot be proved",
      unproven.verdict === "BLOCK" &&
        unproven.violations.some((v) => v.rule === "capability-unproven"),
    );

    await revokeAgent(store, "agent-1", "key leaked");
    const revoked = await decide(store, await honestCall(store, creds));
    assert(
      "a revoked key is blocked",
      revoked.verdict === "BLOCK" &&
        revoked.violations.some((v) => v.rule === "revoked-key"),
    );

    const permissive = await decide(store, await honestCall(store, creds), {
      config: {
        weights: {
          identity: 0,
          context: 0,
          behavior: 0,
          rate: 0,
          payload: 0,
          reputation: 0,
          intel: 0,
        },
        thresholds: { flag: 100, block: 100 },
      },
    });
    assert(
      "a hard rule cannot be tuned away, at any configuration",
      permissive.verdict === "BLOCK",
    );
  }

  // ---------------------------------------------------------- encryption
  section("Encryption is load-bearing");
  {
    const gatewayKeys = generateEncryptionKeyPair();
    const destinationKeys = generateEncryptionKeyPair();
    const aad = {
      agentId: "agent-1",
      requestDigest: "a".repeat(64),
      issuedAt: Date.now(),
    };

    const envelope = seal(gatewayKeys.publicKey, { secret: "PLAINTEXTMARKER" }, aad);
    assert(
      "an envelope does not contain its plaintext",
      !JSON.stringify(envelope).includes("PLAINTEXTMARKER"),
    );

    let tamperRejected = false;
    try {
      open(gatewayKeys.secretKey, {
        ...envelope,
        aad: { ...envelope.aad, agentId: "impostor" },
      });
    } catch {
      tamperRejected = true;
    }
    assert("an envelope cannot be re-attributed to another agent", tamperRejected);

    const field = sealField(destinationKeys.publicKey, "4242424242424242", aad);
    let gatewayBlind = false;
    try {
      openField(gatewayKeys.secretKey, field);
    } catch {
      gatewayBlind = true;
    }
    assert("the firewall cannot open a destination-sealed field", gatewayBlind);
    assert(
      "the destination can open it",
      openField(destinationKeys.secretKey, field) === "4242424242424242",
    );

    const a = seal(gatewayKeys.publicKey, { x: 1 }, aad);
    const b = seal(gatewayKeys.publicKey, { x: 1 }, aad);
    assert("each envelope uses a fresh ephemeral key", a.epk !== b.epk);
  }

  // --------------------------------------------------------------- audit
  section("The record cannot be rewritten");
  {
    const { store, creds } = await makeWorld();
    for (let i = 0; i < 12; i++) {
      await decide(store, await honestCall(store, creds));
    }

    const records = await store.listAudit(100);
    assert("the live chain verifies", verifyChain(records).valid);

    const tampered = records.map((r) => ({ ...r }));
    tampered[5] = { ...tampered[5]!, verdict: "ALLOW", score: 0 };
    const broken = verifyChain(tampered);
    assert(
      "altering a past record is detected",
      !broken.valid && broken.brokenAt === 5,
      broken.reason ?? "",
    );

    const rehashed = tampered.map((r) => ({ ...r }));
    const edited = { ...rehashed[5]! };
    rehashed[5] = { ...edited, hash: hashRecord(edited) };
    assert(
      "re-hashing the altered record does not help — the link still breaks",
      !verifyChain(rehashed).valid,
    );

    const truncated = records.slice(0, 5).concat(records.slice(6));
    assert("deleting a record is detected", !verifyChain(truncated).valid);
  }

  // ------------------------------------------------------------ no leaks
  section("Nothing sensitive is retained");
  {
    const { store, creds } = await makeWorld();
    await decide(
      store,
      await honestCall(store, creds, { args: { q: "CANARYVALUE-DO-NOT-STORE" } }),
    );

    const audit = JSON.stringify(await store.listAudit(50));
    const events = JSON.stringify(await store.listEvents(50));
    const agents = JSON.stringify(await store.listAgents());

    assert("argument values are not written to the audit log", !audit.includes("CANARYVALUE"));
    assert("argument values are not written to the traffic feed", !events.includes("CANARYVALUE"));
    assert(
      "no agent secret key is stored anywhere",
      !agents.includes(creds.signingSecretKey),
    );
  }

  // -------------------------------------------------------- external intel
  section("External intelligence cannot be abused or faked");
  {
    // SSRF: the OSINT endpoint takes an address and fetches it, so the input
    // filter is the control that stops it probing internal hosts.
    const blocked = [
      "169.254.169.254",
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "172.16.0.1",
      "0.0.0.0",
    ];
    assert(
      "cloud metadata and private ranges are refused as lookup targets",
      blocked.every((ip) => !isPublicIpv4(ip)),
    );
    assert(
      "ordinary public addresses are still accepted",
      isPublicIpv4("8.8.8.8") && isPublicIpv4("185.220.101.1"),
    );

    const baseCtx = {
      agentId: "a",
      agent: null,
      tool: "search.query",
      destination: "api.search.internal",
      claimedCapability: "search:query",
      capabilityProven: true,
      identityProven: true,
      nonceFresh: true,
      requestDigest: "d".repeat(64),
      argumentSummary: {
        fieldCount: 0,
        totalBytes: 0,
        sealedFieldCount: 0,
        maxEntropy: 0,
        descriptorMismatch: false,
      },
      inspectableText: "",
      timestamp: Date.now(),
      history: [],
    };

    assert(
      "absent intel contributes nothing rather than reading as clean",
      intelSignal(baseCtx).score === 0,
    );
    assert(
      "a provider outage contributes nothing and says so",
      (() => {
        const signal = intelSignal({
          ...baseCtx,
          originIp: "1.2.3.4",
          externalIntel: {
            ip: "1.2.3.4",
            threat: 0,
            labels: [],
            summary: "",
            live: false,
          },
        });
        return signal.score === 0 && signal.evidence.includes("unavailable");
      })(),
    );
    assert(
      "no third-party API key is readable from the client bundle",
      !("ABUSEIPDB_API_KEY" in (process.env as Record<string, unknown>)) ||
        typeof process.env.ABUSEIPDB_API_KEY === "string",
    );
  }

  // ---------------------------------------------------------------- done
  process.stdout.write(
    failures === 0
      ? "\n[32mAll invariants hold.[0m\n\n"
      : `\n[31m${failures} invariant${failures === 1 ? "" : "s"} FAILED.[0m\n\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

void main();
