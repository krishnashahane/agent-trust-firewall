/**
 * Storage port.
 *
 * The engine talks only to this interface, never to a concrete database. The
 * shipped implementation is in-process (see memory.ts); swapping in Postgres
 * means writing one more implementation, not touching the firewall logic.
 */
import type { AuditRecord } from "../audit/chain.ts";
import type { AgentRecord, TrafficEvent } from "../types.ts";

export interface Store {
  // agents
  putAgent(agent: AgentRecord): Promise<void>;
  getAgent(agentId: string): Promise<AgentRecord | null>;
  listAgents(): Promise<AgentRecord[]>;

  // single-use challenges — the replay defence
  putNonce(nonce: string, agentId: string, expiresAt: number): Promise<void>;
  /** Atomically consume. Returns false if unknown, expired, already used, or
   *  bound to a different agent. */
  consumeNonce(nonce: string, agentId: string, now: number): Promise<boolean>;

  // traffic
  appendEvent(event: TrafficEvent): Promise<void>;
  listEvents(limit: number): Promise<TrafficEvent[]>;
  /** events for one agent within a time window, newest first */
  eventsForAgent(agentId: string, sinceMs: number, now: number): Promise<TrafficEvent[]>;

  // audit
  appendAudit(record: AuditRecord): Promise<void>;
  listAudit(limit: number): Promise<AuditRecord[]>;
  /** records with seq >= fromSeq, ascending, at most `limit` */
  auditFrom(fromSeq: number, limit: number): Promise<AuditRecord[]>;
  auditHead(): Promise<AuditRecord | null>;
  auditLength(): Promise<number>;
}
