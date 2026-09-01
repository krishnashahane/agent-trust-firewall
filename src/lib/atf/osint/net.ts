/**
 * Shared plumbing for outbound OSINT calls.
 *
 * Two jobs: keep third-party latency and failure away from the request path,
 * and make sure an attacker cannot steer our outbound traffic. The second
 * matters more than it looks — an endpoint that takes an IP and fetches it is a
 * server-side request forgery primitive unless the input is constrained to
 * public unicast addresses, so that validation lives here rather than in each
 * provider.
 */

/** Hard ceiling on a single provider call. Demo pages must never hang on one. */
export const PROVIDER_TIMEOUT_MS = 4_000;

/**
 * Reject anything that is not a public IPv4 unicast address.
 *
 * Private, loopback, link-local, CGNAT, multicast and reserved ranges are all
 * refused: those are the addresses an SSRF payload would reach for, and no
 * legitimate threat-intel lookup needs them. IPv6 is refused outright rather
 * than half-validated — the providers used here are IPv4-oriented, and a
 * partially-correct IPv6 filter is worse than an honest "unsupported".
 */
export function isPublicIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;

  const octets: number[] = [];
  for (const part of parts) {
    // Reject leading zeros: "010" can be read as octal by some resolvers.
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false;
    const n = Number(part);
    if (n > 255) return false;
    octets.push(n);
  }

  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return false; // "this network"
  if (a === 10) return false; // RFC1918
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local (cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 168) return false; // RFC1918
  if (a === 192 && b === 0) return false; // IETF protocol assignments
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a >= 224) return false; // multicast + reserved + broadcast
  return true;
}

export class ProviderError extends Error {}

/**
 * Fetch JSON with a timeout the caller cannot exceed.
 *
 * Non-2xx is not automatically an error: several of these APIs answer "I have
 * nothing on this indicator" with a 404 and a useful body, and treating that as
 * a failure would throw away a real, clean result. Callers decide what a status
 * means for their provider.
 */
export async function getJson(
  url: string,
  init: { headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    init.timeoutMs ?? PROVIDER_TIMEOUT_MS,
  );
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json", ...init.headers },
      // These are public threat-intel reads; never send credentials along.
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
    });
    const text = await response.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      throw new ProviderError("provider returned a non-JSON body");
    }
    return { status: response.status, body };
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw new ProviderError(
      error instanceof Error && error.name === "AbortError"
        ? "provider timed out"
        : "provider request failed",
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Narrow an unknown JSON body to a record without trusting its shape. */
export const asRecord = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

export const asStringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string").slice(0, 32)
    : [];

export const asNumberArray = (value: unknown): number[] =>
  Array.isArray(value)
    ? value.filter((v): v is number => typeof v === "number").slice(0, 64)
    : [];
