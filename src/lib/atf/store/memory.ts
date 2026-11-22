/**
 * In-process store.
 *
 * Deliberately self-contained: ATF needs no database to demonstrate that the
 * firewall works, and every credential we do not require is a credential that
 * cannot leak. State lives for the lifetime of the process, which on a
 * serverless host means it resets on cold start — a real limitation, stated
 * plainly in the UI rather than disguised.
 *
 * Collections are bounded. An append-only log with no ceiling is a memory
 * exhaustion bug that an attacker can trigger for free.
 */
import type { AuditRecord } from "../audit/chain.ts";
import type { Store } from "./port.ts";
import type { AgentRecord, TrafficEvent } from "../types.ts";

const MAX_EVENTS = 2_000;
const MAX_AUDIT = 2_000;
const MAX_NONCES = 10_000;

interface NonceEntry {
  agentId: string;
  expiresAt: number;
}

export class MemoryStore implements Store {
  private agents = new Map<string, AgentRecord>();
  private nonces = new Map<string, NonceEntry>();
  private events: TrafficEvent[] = [];
  private audit: AuditRecord[] = [];
  /** kept separate from `audit` so trimming old records cannot silently reset
   *  the chain: seq numbers keep counting from the true head. */
  private auditCount = 0;

  async putAgent(agent: AgentRecord): Promise<void> {
    this.agents.set(agent.agentId, agent);
  }

  async getAgent(agentId: string): Promise<AgentRecord | null> {
    return this.agents.get(agentId) ?? null;
  }

  async listAgents(): Promise<AgentRecord[]> {
    return [...this.agents.values()].sort((a, b) => b.registeredAt - a.registeredAt);
  }

  async putNonce(nonce: string, agentId: string, expiresAt: number): Promise<void> {
    if (this.nonces.size >= MAX_NONCES) this.evictExpiredNonces(Date.now());
    if (this.nonces.size >= MAX_NONCES) {
      // still full: drop the oldest insertion rather than grow without bound
      const oldest = this.nonces.keys().next();
      if (!oldest.done) this.nonces.delete(oldest.value);
    }
    this.nonces.set(nonce, { agentId, expiresAt });
  }

  /**
   * Single-use by construction: the entry is deleted on the first attempt,
   * whether or not that attempt was valid. Node runs this on one thread, so
   * delete-then-check cannot interleave.
   */
  async consumeNonce(nonce: string, agentId: string, now: number): Promise<boolean> {
    const entry = this.nonces.get(nonce);
    if (!entry) return false;
    this.nonces.delete(nonce);
    if (entry.expiresAt < now) return false;
    return entry.agentId === agentId;
  }

  private evictExpiredNonces(now: number): void {
    for (const [nonce, entry] of this.nonces) {
      if (entry.expiresAt < now) this.nonces.delete(nonce);
    }
  }

  async appendEvent(event: TrafficEvent): Promise<void> {
    this.events.push(event);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
  }

  async listEvents(limit: number): Promise<TrafficEvent[]> {
    return this.events.slice(-Math.max(0, limit)).reverse();
  }

  async eventsForAgent(agentId: string, sinceMs: number, now: number): Promise<TrafficEvent[]> {
    const cutoff = now - sinceMs;
    const out: TrafficEvent[] = [];
    for (let i = this.events.length - 1; i >= 0; i--) {
      const event = this.events[i] as TrafficEvent;
      if (event.timestamp < cutoff) break;
      if (event.agentId === agentId) out.push(event);
    }
    return out;
  }

  async appendAudit(record: AuditRecord): Promise<void> {
    this.audit.push(record);
    this.auditCount++;
    if (this.audit.length > MAX_AUDIT) this.audit.splice(0, this.audit.length - MAX_AUDIT);
  }

  async listAudit(limit: number): Promise<AuditRecord[]> {
    return this.audit.slice(-Math.max(0, limit));
  }

  async auditFrom(fromSeq: number, limit: number): Promise<AuditRecord[]> {
    const first = this.audit[0];
    if (!first) return [];
    const start = Math.max(0, fromSeq - first.seq);
    return this.audit.slice(start, start + Math.max(0, limit));
  }

  async auditHead(): Promise<AuditRecord | null> {
    return this.audit[this.audit.length - 1] ?? null;
  }

  async auditLength(): Promise<number> {
    return this.auditCount;
  }
}
