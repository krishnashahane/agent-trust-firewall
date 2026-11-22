/**
 * End-to-end smoke test against a running deployment, acting as a real agent.
 *
 *   ATF_URL=http://localhost:3000 ATF_ADMIN_TOKEN=… npm run smoke
 *
 * Enrols a fresh agent, makes a sealed call, reuses the challenge returned with
 * the verdict, then tries a replay and a capability escalation. Exits non-zero
 * if any step does not behave as the firewall promises.
 */
import { generateKeyPair } from "../src/lib/atf/identity/schnorr.ts";
import { generateEncryptionKeyPair, open } from "../src/lib/atf/crypto/e2ee.ts";
import { capabilityRoot } from "../src/lib/atf/identity/merkle.ts";
import { sealCall, signCall, type SignedCall } from "../src/lib/atf/client.ts";

const BASE = (process.env.ATF_URL ?? "http://localhost:3000").replace(/\/$/, "");
const TOKEN = process.env.ATF_ADMIN_TOKEN ?? "";

let failures = 0;
function check(name: string, ok: boolean, detail = ""): void {
  process.stdout.write(`${ok ? "  \x1b[32m✓\x1b[0m" : "  \x1b[31m✗"} ${name}${ok ? "" : "\x1b[0m"}${!ok && detail ? ` — ${detail}` : ""}\n`);
  if (!ok) failures++;
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  const response = await fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: response.status, json: (await response.json()) as Record<string, unknown> };
}

interface Verdict {
  verdict: string;
  explanation: string;
  nextChallenge: { nonce: string } | null;
}

async function main(): Promise<void> {
  process.stdout.write(`\nAgent Trust Firewall smoke test against ${BASE}\n\n`);
  if (!TOKEN) throw new Error("Set ATF_ADMIN_TOKEN to the deployment's admin token.");

  const agentId = `smoke-${Date.now().toString(36)}`;
  const signing = generateKeyPair();
  const encryption = generateEncryptionKeyPair();
  const capabilities = ["search:query"];
  const enrolment = {
    agentId,
    displayName: "Smoke Test Agent",
    signingPublicKey: signing.publicKey,
    encryptionPublicKey: encryption.publicKey,
    capabilityRoot: capabilityRoot(capabilities),
  };

  const anonymous = await post("/api/agents/register", enrolment);
  check("enrolment without the admin token is refused", anonymous.status === 401 || anonymous.status === 503);

  const enrolled = await post("/api/agents/register", enrolment, { authorization: `Bearer ${TOKEN}` });
  check("enrolment with the admin token succeeds", enrolled.status === 201, JSON.stringify(enrolled.json));

  const { publicKey: gatewayKey } = (await (await fetch(BASE + "/api/gateway/pubkey")).json()) as {
    publicKey: string;
  };
  const credentials = { agentId, signingSecretKey: signing.secretKey, capabilities };

  const submit = async (call: SignedCall): Promise<Verdict> => {
    const { json } = await post("/api/gateway/intercept", {
      envelope: sealCall(gatewayKey, call),
      replyTo: encryption.publicKey,
    });
    return open(encryption.secretKey, json["sealed"] as never) as Verdict;
  };
  const searchCall = (nonce: string) =>
    signCall(credentials, {
      tool: "search.query",
      destination: "api.search.internal",
      capability: "search:query",
      args: { q: "quarterly report" },
      nonce,
    });

  const { json: challenge } = await post("/api/agents/challenge", { agentId });
  const first = searchCall(challenge["nonce"] as string);
  const firstVerdict = await submit(first);
  check("a sealed, honest call is allowed", firstVerdict.verdict === "ALLOW", firstVerdict.explanation);
  check("the verdict carries the next challenge", typeof firstVerdict.nextChallenge?.nonce === "string");

  const second = await submit(searchCall(firstVerdict.nextChallenge?.nonce ?? ""));
  check("the returned challenge works for the next call", second.verdict === "ALLOW", second.explanation);

  const replay = await submit(first);
  check("replaying the first call is blocked", replay.verdict === "BLOCK", replay.explanation);
  check("a blocked replay gets no new challenge", replay.nextChallenge === null);

  const { json: c3 } = await post("/api/agents/challenge", { agentId });
  const escalation = await submit(
    signCall(credentials, {
      tool: "payments.charge",
      destination: "api.payments.internal",
      capability: "payments:charge",
      args: { amountMinor: 990000, currency: "USD" },
      nonce: c3["nonce"] as string,
    }),
  );
  check("calling a tool the agent was never granted is blocked", escalation.verdict === "BLOCK", escalation.explanation);

  const checkpoint = (await (await fetch(BASE + "/api/audit/checkpoint")).json()) as { seq: number; hash: string };
  const consistency = (await (
    await fetch(`${BASE}/api/audit/verify?seq=${checkpoint.seq}&hash=${checkpoint.hash}`)
  ).json()) as { checkpoint: { status: string } };
  check("a fresh audit checkpoint is consistent with the log", consistency.checkpoint.status === "consistent");

  process.stdout.write(failures === 0 ? "\n\x1b[32mAll smoke checks passed.\x1b[0m\n" : `\n\x1b[31m${failures} check(s) failed.\x1b[0m\n`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  process.stderr.write(`\nSmoke test could not run: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
