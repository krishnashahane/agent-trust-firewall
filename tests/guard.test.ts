import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  HttpError,
  JSON_LIMIT_BYTES,
  limit,
  originGuard,
  readJson,
  requireAdmin,
} from "@/lib/guard";

const req = (init: { origin?: string; host?: string; body?: string; ip?: string }) => {
  const headers = new Headers();
  if (init.origin) headers.set("origin", init.origin);
  if (init.host) headers.set("host", init.host);
  if (init.ip) headers.set("x-forwarded-for", init.ip);
  headers.set("content-type", "application/json");
  return new Request("https://agent-trust-firewall.vercel.app/api/test", {
    method: "POST",
    headers,
    body: init.body,
  });
};

describe("origin guard", () => {
  it("allows a same-origin browser request", () => {
    expect(() =>
      originGuard(
        req({ origin: "https://agent-trust-firewall.vercel.app", host: "agent-trust-firewall.vercel.app" }),
      ),
    ).not.toThrow();
  });

  it("rejects a cross-site browser request", () => {
    expect(() =>
      originGuard(req({ origin: "https://evil.example", host: "agent-trust-firewall.vercel.app" })),
    ).toThrow(HttpError);
  });

  it("rejects a malformed origin rather than ignoring it", () => {
    expect(() => originGuard(req({ origin: "not a url", host: "h" }))).toThrow(HttpError);
  });

  it("allows a non-browser caller, which sends no Origin", () => {
    // An agent or curl carries no ambient credentials, so there is nothing for
    // a cross-site page to abuse on its behalf.
    expect(() => originGuard(req({ host: "agent-trust-firewall.vercel.app" }))).not.toThrow();
  });

  it("rejects a request with an Origin but no Host", () => {
    expect(() => originGuard(req({ origin: "https://a.example" }))).toThrow(HttpError);
  });
});

describe("rate limiting", () => {
  it("allows up to the limit then rejects with 429", () => {
    const ip = `10.0.0.${Math.floor(Math.random() * 250)}`;
    const request = req({ ip, host: "h" });
    for (let i = 0; i < 5; i++) {
      expect(() => limit(request, `test-${ip}`, 5)).not.toThrow();
    }
    try {
      limit(request, `test-${ip}`, 5);
      throw new Error("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(HttpError);
      expect((error as HttpError).status).toBe(429);
    }
  });

  it("keeps separate budgets per route", () => {
    const ip = "10.9.9.9";
    const request = req({ ip, host: "h" });
    for (let i = 0; i < 3; i++) limit(request, "route-a", 3);
    expect(() => limit(request, "route-b", 3)).not.toThrow();
  });

  it("keeps separate budgets per client", () => {
    for (let i = 0; i < 3; i++) limit(req({ ip: "1.1.1.1", host: "h" }), "shared", 3);
    expect(() => limit(req({ ip: "2.2.2.2", host: "h" }), "shared", 3)).not.toThrow();
  });

  it("resets after the window", () => {
    const request = req({ ip: "3.3.3.3", host: "h" });
    limit(request, "windowed", 1, 1);
    // A window of 1ms has certainly elapsed by the next event-loop turn.
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(() => limit(request, "windowed", 1, 1)).not.toThrow();
        resolve();
      }, 5);
    });
  });
});

describe("body parsing", () => {
  const schema = z.object({ name: z.string().min(1), count: z.number() });

  it("parses a valid body", async () => {
    const body = await readJson(
      req({ host: "h", body: JSON.stringify({ name: "a", count: 1 }) }),
      schema,
    );
    expect(body).toEqual({ name: "a", count: 1 });
  });

  it("rejects invalid JSON", async () => {
    await expect(readJson(req({ host: "h", body: "{not json" }), schema)).rejects.toThrow(
      HttpError,
    );
  });

  it("rejects a body that fails the schema", async () => {
    await expect(
      readJson(req({ host: "h", body: JSON.stringify({ name: "" }) }), schema),
    ).rejects.toThrow(HttpError);
  });

  it("names the failing fields but never echoes their values back", async () => {
    try {
      await readJson(
        req({ host: "h", body: JSON.stringify({ name: "", count: "SECRETVALUE" }) }),
        schema,
      );
      throw new Error("should have thrown");
    } catch (error) {
      const message = (error as HttpError).publicMessage;
      expect(message).toContain("name");
      expect(message).not.toContain("SECRETVALUE");
    }
  });

  it("rejects an oversized body", async () => {
    const huge = JSON.stringify({ name: "x".repeat(JSON_LIMIT_BYTES + 10), count: 1 });
    await expect(readJson(req({ host: "h", body: huge }), schema)).rejects.toThrow(
      HttpError,
    );
  });

  it("rejects a JSON array where an object is required", async () => {
    await expect(readJson(req({ host: "h", body: "[1,2,3]" }), schema)).rejects.toThrow(
      HttpError,
    );
  });

  it("rejects a null body", async () => {
    await expect(readJson(req({ host: "h", body: "null" }), schema)).rejects.toThrow(
      HttpError,
    );
  });
});

describe("admin enrolment guard", () => {
  const TOKEN = "t".repeat(48);
  const withAuth = (value?: string) =>
    new Request("https://example.test/api/agents/register", {
      method: "POST",
      headers: value ? { authorization: value } : {},
    });
  const status = (fn: () => void) => {
    try {
      fn();
      return 200;
    } catch (error) {
      return (error as HttpError).status;
    }
  };

  afterEach(() => vi.unstubAllEnvs());

  it("is disabled, not open, when no token is configured", () => {
    vi.stubEnv("ATF_ADMIN_TOKEN", "");
    expect(status(() => requireAdmin(withAuth(`Bearer ${TOKEN}`)))).toBe(503);
  });

  it("refuses to run with a token too short to be a secret", () => {
    vi.stubEnv("ATF_ADMIN_TOKEN", "short");
    expect(status(() => requireAdmin(withAuth("Bearer short")))).toBe(503);
  });

  it("rejects a missing, malformed or wrong token", () => {
    vi.stubEnv("ATF_ADMIN_TOKEN", TOKEN);
    expect(status(() => requireAdmin(withAuth()))).toBe(401);
    expect(status(() => requireAdmin(withAuth(TOKEN)))).toBe(401);
    expect(status(() => requireAdmin(withAuth(`Bearer ${TOKEN}x`)))).toBe(401);
    expect(status(() => requireAdmin(withAuth("Bearer ")))).toBe(401);
  });

  it("accepts the configured token", () => {
    vi.stubEnv("ATF_ADMIN_TOKEN", TOKEN);
    expect(status(() => requireAdmin(withAuth(`Bearer ${TOKEN}`)))).toBe(200);
  });
});
