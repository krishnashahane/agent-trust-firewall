/**
 * Per-visitor configuration sandboxes.
 *
 * The tuning page lets anyone move the risk weights and thresholds. In the
 * first version those writes landed on the single shared gateway config, which
 * meant any anonymous visitor could change what every other concurrent visitor
 * saw — and could set the block threshold to 100 for everybody. For a product
 * whose pitch is that it is a firewall, an unauthenticated global state
 * mutation is the worst possible finding, so the shared config is now
 * read-only and each visitor gets their own sandboxed copy.
 *
 * The session id is an opaque random value in an HttpOnly cookie. It is not an
 * identity and grants nothing: its only job is to keep one visitor's slider
 * experiments off another visitor's screen. Sandboxes are bounded and expire,
 * so this cannot be used to grow server memory without limit.
 */
import { bytesToHex, random } from "./crypto/primitives.ts";
import { DEFAULT_RISK_CONFIG, type RiskConfig } from "./risk/config.ts";

export const SESSION_COOKIE = "atf_session";
/** Long enough to survive a browsing session, short enough to reclaim memory. */
const TTL_MS = 60 * 60_000;
const MAX_SESSIONS = 2_000;

interface SessionState {
  config: RiskConfig;
  expiresAt: number;
}

declare global {
  var __atfSessions: Map<string, SessionState> | undefined;
}

const sessions = (globalThis.__atfSessions ??= new Map<string, SessionState>());

function evict(now: number): void {
  for (const [id, state] of sessions) {
    if (state.expiresAt <= now) sessions.delete(id);
  }
  // Still full after expiry sweep: drop oldest insertions rather than grow.
  while (sessions.size > MAX_SESSIONS) {
    const oldest = sessions.keys().next();
    if (oldest.done) break;
    sessions.delete(oldest.value);
  }
}

export const newSessionId = (): string => bytesToHex(random(16));

/** Session ids are opaque hex; anything else is treated as absent. */
export const isValidSessionId = (value: string | undefined): value is string =>
  typeof value === "string" && /^[0-9a-f]{32}$/.test(value);

/**
 * The config this visitor should be scored against: their sandbox if they have
 * made a change, otherwise the shared read-only default.
 */
export function configFor(sessionId: string | undefined, now = Date.now()): RiskConfig {
  if (!isValidSessionId(sessionId)) return DEFAULT_RISK_CONFIG;
  const state = sessions.get(sessionId);
  if (!state || state.expiresAt <= now) return DEFAULT_RISK_CONFIG;
  return state.config;
}

/** True when this visitor has an active sandbox, so the UI can say so. */
export function hasSandbox(sessionId: string | undefined, now = Date.now()): boolean {
  if (!isValidSessionId(sessionId)) return false;
  const state = sessions.get(sessionId);
  return Boolean(state && state.expiresAt > now);
}

export function setSessionConfig(
  sessionId: string,
  config: RiskConfig,
  now = Date.now(),
): void {
  sessions.set(sessionId, { config, expiresAt: now + TTL_MS });
  // Evict *after* inserting, or the new entry pushes the map one over the cap.
  evict(now);
}

/** Discard a sandbox, returning the visitor to the shared defaults. */
export function clearSessionConfig(sessionId: string): void {
  sessions.delete(sessionId);
}

/** Test seam. */
export function resetSessions(): void {
  sessions.clear();
}

export const sessionCount = (): number => sessions.size;
