/**
 * One-time seeding of the durable store.
 *
 * Run against a freshly provisioned database:  npm run seed
 *
 * This exists because seeding is genuinely expensive — every call is a real
 * challenge, a real Schnorr proof and a real scoring pass, which against a
 * remote database is hundreds of statements and tens of seconds. Doing that
 * inside a request would reintroduce the cold-start timeouts the app was just
 * fixed for, so it is a deployment step instead.
 *
 * Safe to re-run: it returns early if the store already holds traffic.
 */
import { getGateway } from "../src/lib/atf/gateway.ts";
import { seedDemoWorld } from "../src/lib/atf/demo/seed.ts";
import { verifyChain } from "../src/lib/atf/audit/chain.ts";

const started = Date.now();
const gateway = await getGateway();

process.stdout.write(`storage: ${gateway.storage}\n`);
if (gateway.storage !== "postgres") {
  process.stdout.write(
    "DATABASE_URL is not set, so this would seed an in-process store that\n" +
      "disappears when the script exits. Nothing to do.\n",
  );
  process.exit(0);
}

const before = await gateway.store.listEvents(1);
if (before.length > 0) {
  process.stdout.write("Already seeded; leaving the existing history alone.\n");
  process.exit(0);
}

await seedDemoWorld(gateway);

const agents = await gateway.store.listAgents();
const events = await gateway.store.listEvents(500);
const chain = verifyChain(await gateway.store.listAudit(2000));

process.stdout.write(
  `seeded in ${((Date.now() - started) / 1000).toFixed(1)}s\n` +
    `  agents: ${agents.length}\n` +
    `  events: ${events.length}\n` +
    `  audit chain: ${chain.valid ? "valid" : `BROKEN at ${chain.brokenAt}`} (${chain.length} records)\n`,
);
process.exit(chain.valid ? 0 : 1);
