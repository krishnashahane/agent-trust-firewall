/**
 * Challenge issuance.
 *
 * The replay defence. Each challenge is 32 bytes of CSPRNG output, bound to one
 * agent, valid for a short window, and spendable exactly once. A proof captured
 * off the wire is therefore useless: replaying it means replaying its nonce, and
 * the nonce is already gone.
 */
import { bytesToHex, random } from "../crypto/primitives.ts";
import type { Store } from "../store/port.ts";

/** Short enough that a stolen challenge has little time to be useful, long
 *  enough that an honest agent on a slow link still completes its call. */
export const NONCE_TTL_MS = 120_000;

export interface Challenge {
  nonce: string;
  expiresAt: number;
}

export async function issueChallenge(
  store: Store,
  agentId: string,
  now = Date.now(),
): Promise<Challenge> {
  const nonce = bytesToHex(random(32));
  const expiresAt = now + NONCE_TTL_MS;
  await store.putNonce(nonce, agentId, expiresAt);
  return { nonce, expiresAt };
}
