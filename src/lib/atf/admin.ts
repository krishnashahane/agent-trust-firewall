/**
 * Operator authentication for enrolment.
 *
 * Enrolment decides which keys the firewall trusts and which capability root
 * they answer to, so an open enrolment endpoint lets anyone grant themselves
 * any capability and then pass every check honestly. This fails closed: with
 * no token configured, enrolment is disabled rather than open.
 *
 * Framework-free so `npm run verify` can assert it directly.
 */
import { tagged, timingSafeEqual, utf8 } from "./crypto/primitives.ts";

/** Shorter tokens are refused outright rather than accepted as weak. */
export const ADMIN_TOKEN_MIN_LENGTH = 32;

export type AdminCheck = "ok" | "disabled" | "unauthorized";

export const adminConfigured = (token = process.env.ATF_ADMIN_TOKEN): boolean =>
  (token?.length ?? 0) >= ADMIN_TOKEN_MIN_LENGTH;

/**
 * Check an `Authorization` header against the configured token. Both sides are
 * hashed first, so the comparison is constant-time and length-independent.
 */
export function checkAdmin(
  authorization: string | null,
  token = process.env.ATF_ADMIN_TOKEN,
): AdminCheck {
  if (!token || !adminConfigured(token)) return "disabled";
  const header = authorization ?? "";
  const presented = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!presented) return "unauthorized";
  const match = timingSafeEqual(
    tagged("atf/admin-token/v1", utf8(presented)),
    tagged("atf/admin-token/v1", utf8(token)),
  );
  return match ? "ok" : "unauthorized";
}
