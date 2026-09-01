/**
 * Route guards.
 *
 * Every API route composes these in the same order:
 *
 *   originGuard -> limit -> readJson(schema) -> handler
 *
 * The order matters. Cross-site requests are rejected before we spend a rate
 * limit slot on them; the rate limit is spent before we parse a body; and no
 * handler ever sees input that has not been through a schema.
 */
import { NextResponse } from "next/server";
import { z } from "zod";
import { bytesToHex, random } from "./atf/crypto/primitives.ts";

export const JSON_LIMIT_BYTES = 512 * 1024;

/** ------------------------------------------------------------------ errors */

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly publicMessage: string,
  ) {
    super(publicMessage);
  }
}

/**
 * Log the real error server-side, return an opaque reference. A client learns
 * that something failed and gets an id to quote; it never learns what.
 */
export function fail(error: unknown): NextResponse {
  if (error instanceof HttpError) {
    return NextResponse.json(
      { error: error.publicMessage },
      { status: error.status, headers: NO_STORE },
    );
  }
  const reference = bytesToHex(random(8));
  console.error(`[atf] unhandled error ref=${reference}`, error);
  return NextResponse.json(
    { error: "Request could not be completed.", reference },
    { status: 500, headers: NO_STORE },
  );
}

export const NO_STORE = { "cache-control": "no-store" } as const;

export const ok = (body: unknown, status = 200): NextResponse =>
  NextResponse.json(body, { status, headers: NO_STORE });

/** ------------------------------------------------------------ origin guard */

/**
 * Reject cross-site browser requests to state-changing endpoints. Same-origin
 * fetches from the dashboard send Origin matching the host; a cross-site page
 * cannot forge that header. Non-browser callers (an agent, curl) send no Origin
 * at all, which is allowed — they carry no ambient credentials to abuse.
 */
export function originGuard(request: Request): void {
  const origin = request.headers.get("origin");
  if (!origin) return;
  let originHost: string;
  try {
    originHost = new URL(origin).host;
  } catch {
    throw new HttpError(403, "Invalid origin.");
  }
  const host = request.headers.get("host");
  if (!host || originHost !== host) {
    throw new HttpError(403, "Cross-site requests are not accepted here.");
  }
}

/** ------------------------------------------------------------- rate limits */

interface Bucket {
  count: number;
  resetAt: number;
}

declare global {
  var __atfBuckets: Map<string, Bucket> | undefined;
}

const buckets = (globalThis.__atfBuckets ??= new Map<string, Bucket>());
const MAX_BUCKETS = 20_000;

/**
 * Fixed-window limiter, per client per route. In-process, matching the rest of
 * ATF's zero-dependency posture: it bounds one instance, and is honest about
 * being per-instance rather than pretending to be a distributed limit.
 */
export function limit(
  request: Request,
  route: string,
  max: number,
  windowMs = 60_000,
): void {
  const now = Date.now();
  if (buckets.size > MAX_BUCKETS) {
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt < now) buckets.delete(key);
    }
    if (buckets.size > MAX_BUCKETS) buckets.clear();
  }

  const key = `${route}:${clientKey(request)}`;
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return;
  }
  bucket.count++;
  if (bucket.count > max) {
    throw new HttpError(429, "Too many requests. Slow down and try again shortly.");
  }
}

/** Vercel sets x-forwarded-for; the left-most entry is the client. */
function clientKey(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0]?.trim();
  return ip && ip.length <= 45 ? ip : "unknown";
}

/** ------------------------------------------------------------ body parsing */

export async function readJson<T>(
  request: Request,
  schema: z.ZodType<T>,
): Promise<T> {
  const declared = request.headers.get("content-length");
  if (declared && Number(declared) > JSON_LIMIT_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }

  const text = await request.text();
  // A missing or lying content-length is checked again against reality.
  if (text.length > JSON_LIMIT_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }

  const result = schema.safeParse(parsed);
  if (!result.success) {
    // Field paths help a legitimate integrator; values are never echoed back.
    const fields = result.error.issues
      .map((issue) => issue.path.join(".") || "(root)")
      .slice(0, 8);
    throw new HttpError(400, `Invalid request: ${[...new Set(fields)].join(", ")}`);
  }
  return result.data;
}
