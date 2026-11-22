/**
 * Durable storage.
 *
 * The in-memory store was always described as a stand-in behind an interface,
 * and this is that interface's second implementation. It matters more here than
 * in most products: the audit log's whole argument is that a record cannot be
 * quietly rewritten, and a log that evaporates on cold start only makes that
 * argument for as long as one serverless instance happens to live.
 *
 * Three properties this implementation has to preserve, all of which the
 * in-memory version got for free from being single-threaded:
 *
 *  1. **The audit chain is strictly ordered.** `seq` is assigned by the caller
 *     from the current head, so two concurrent appends must not be able to
 *     claim the same one. A unique index on `seq` turns that race into a
 *     failed insert rather than a silently forked chain.
 *  2. **A nonce is spent exactly once.** Consumption is a single conditional
 *     DELETE ... RETURNING, so two racing requests cannot both see it as
 *     unspent. Doing this as SELECT-then-DELETE would reintroduce the replay
 *     the nonce exists to prevent.
 *  3. **Nothing unbounded is read.** Every list is limited and indexed.
 */
import { neon } from "@neondatabase/serverless";
import type { AuditRecord } from "../audit/chain.ts";
import type { Store } from "./port.ts";
import type { AgentRecord, TrafficEvent } from "../types.ts";

type Sql = ReturnType<typeof neon>;

/**
 * Timestamps are epoch milliseconds and the columns are BIGINT, so a
 * fractional value is a type error rather than a rounding nicety. Coerced here
 * as well as at the call sites: the store is the last place that can enforce
 * it, and a caller passing a float should not be able to corrupt the schema.
 */
const asEpoch = (value: number): number => Math.round(value);

/** Lazily created: evaluating this at module scope would break `next build`
 *  on any deploy where the database is not yet provisioned. */
let client: Sql | null = null;

function sql(): Sql {
  if (!client) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is not configured");
    client = neon(url);
  }
  return client;
}

export const isPostgresConfigured = (): boolean =>
  typeof process.env.DATABASE_URL === "string" && process.env.DATABASE_URL.length > 0;

/**
 * Create the schema if it is absent.
 *
 * Run once per cold start rather than as a migration step: this is a single
 * self-contained schema with no versioned history to manage, and making it
 * idempotent is simpler and harder to get wrong than shipping a migration
 * runner for four tables.
 */
export async function ensureSchema(): Promise<void> {
  const db = sql();
  await db`
    CREATE TABLE IF NOT EXISTS atf_agents (
      agent_id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      registered_at BIGINT NOT NULL
    )`;
  await db`
    CREATE TABLE IF NOT EXISTS atf_nonces (
      nonce TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      expires_at BIGINT NOT NULL
    )`;
  await db`
    CREATE TABLE IF NOT EXISTS atf_events (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      data JSONB NOT NULL
    )`;
  await db`
    CREATE TABLE IF NOT EXISTS atf_audit (
      seq BIGINT PRIMARY KEY,
      id TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      data JSONB NOT NULL
    )`;
  // The two lookups that would otherwise scan: an agent's recent history, and
  // the newest events for the console feed.
  await db`CREATE INDEX IF NOT EXISTS atf_events_agent_ts ON atf_events (agent_id, timestamp DESC)`;
  await db`CREATE INDEX IF NOT EXISTS atf_events_ts ON atf_events (timestamp DESC)`;
  await db`CREATE INDEX IF NOT EXISTS atf_nonces_expiry ON atf_nonces (expires_at)`;
  // Earlier releases stored each agent's full capability list. The firewall
  // only needs the root, so any list left over from then is removed.
  await db`
    UPDATE atf_agents SET data = data - 'declaredCapabilities'
    WHERE data ? 'declaredCapabilities'`;
}

export class PostgresStore implements Store {
  /* --------------------------------------------------------------- agents */

  async putAgent(agent: AgentRecord): Promise<void> {
    await sql()`
      INSERT INTO atf_agents (agent_id, data, registered_at)
      VALUES (${agent.agentId}, ${JSON.stringify(agent)}::jsonb, ${asEpoch(agent.registeredAt)})
      ON CONFLICT (agent_id) DO UPDATE
        SET data = EXCLUDED.data, registered_at = EXCLUDED.registered_at`;
  }

  async getAgent(agentId: string): Promise<AgentRecord | null> {
    const rows = (await sql()`
      SELECT data FROM atf_agents WHERE agent_id = ${agentId} LIMIT 1
    `) as { data: AgentRecord }[];
    return rows[0]?.data ?? null;
  }

  async listAgents(): Promise<AgentRecord[]> {
    const rows = (await sql()`
      SELECT data FROM atf_agents ORDER BY registered_at DESC LIMIT 200
    `) as { data: AgentRecord }[];
    return rows.map((r) => r.data);
  }

  /* --------------------------------------------------------------- nonces */

  async putNonce(nonce: string, agentId: string, expiresAt: number): Promise<void> {
    await sql()`
      INSERT INTO atf_nonces (nonce, agent_id, expires_at)
      VALUES (${nonce}, ${agentId}, ${asEpoch(expiresAt)})
      ON CONFLICT (nonce) DO NOTHING`;
  }

  /**
   * Spend a challenge.
   *
   * One statement, deliberately. The DELETE is the claim: whichever request
   * wins gets the row back and every other gets nothing, so a replayed proof
   * cannot be accepted twice even under concurrent submission. The agent and
   * expiry are checked *after* the delete, because a challenge offered to an
   * agent is consumed by the attempt whether or not the attempt was valid.
   */
  async consumeNonce(nonce: string, agentId: string, now: number): Promise<boolean> {
    const rows = (await sql()`
      DELETE FROM atf_nonces WHERE nonce = ${nonce}
      RETURNING agent_id, expires_at
    `) as { agent_id: string; expires_at: string }[];

    const row = rows[0];
    if (!row) return false;
    if (Number(row.expires_at) < now) return false;
    return row.agent_id === agentId;
  }

  /* --------------------------------------------------------------- events */

  async appendEvent(event: TrafficEvent): Promise<void> {
    await sql()`
      INSERT INTO atf_events (id, agent_id, timestamp, data)
      VALUES (${event.id}, ${event.agentId}, ${asEpoch(event.timestamp)}, ${JSON.stringify(event)}::jsonb)
      ON CONFLICT (id) DO NOTHING`;
  }

  async listEvents(limit: number): Promise<TrafficEvent[]> {
    const capped = Math.min(500, Math.max(0, limit));
    const rows = (await sql()`
      SELECT data FROM atf_events ORDER BY timestamp DESC, id DESC LIMIT ${capped}
    `) as { data: TrafficEvent }[];
    return rows.map((r) => r.data);
  }

  async eventsForAgent(
    agentId: string,
    sinceMs: number,
    now: number,
  ): Promise<TrafficEvent[]> {
    const rows = (await sql()`
      SELECT data FROM atf_events
      WHERE agent_id = ${agentId} AND timestamp >= ${asEpoch(now - sinceMs)}
      ORDER BY timestamp DESC LIMIT 200
    `) as { data: TrafficEvent }[];
    return rows.map((r) => r.data);
  }

  /* ---------------------------------------------------------------- audit */

  /**
   * Append one audit record.
   *
   * `seq` is the primary key, so a second writer that computed the same `seq`
   * from the same head fails the insert instead of forking the chain. That is
   * the behaviour we want: better a rejected append than two records claiming
   * the same position, which would make `verifyChain` meaningless.
   */
  async appendAudit(record: AuditRecord): Promise<void> {
    await sql()`
      INSERT INTO atf_audit (seq, id, timestamp, data)
      VALUES (${asEpoch(record.seq)}, ${record.id}, ${asEpoch(record.timestamp)}, ${JSON.stringify(record)}::jsonb)`;
  }

  /** Oldest-first, as `verifyChain` requires. */
  async listAudit(limit: number): Promise<AuditRecord[]> {
    const capped = Math.min(2000, Math.max(0, limit));
    const rows = (await sql()`
      SELECT data FROM (
        SELECT data, seq FROM atf_audit ORDER BY seq DESC LIMIT ${capped}
      ) recent ORDER BY seq ASC
    `) as { data: AuditRecord }[];
    return rows.map((r) => r.data);
  }

  async auditHead(): Promise<AuditRecord | null> {
    const rows = (await sql()`
      SELECT data FROM atf_audit ORDER BY seq DESC LIMIT 1
    `) as { data: AuditRecord }[];
    return rows[0]?.data ?? null;
  }

  async auditLength(): Promise<number> {
    const rows = (await sql()`SELECT COUNT(*)::int AS n FROM atf_audit`) as {
      n: number;
    }[];
    return rows[0]?.n ?? 0;
  }

  /* ------------------------------------------------------------ housekeeping */

  /** Expired challenges are dead weight; drop them opportunistically. */
  async pruneNonces(now = Date.now()): Promise<void> {
    await sql()`DELETE FROM atf_nonces WHERE expires_at < ${asEpoch(now)}`;
  }
}
