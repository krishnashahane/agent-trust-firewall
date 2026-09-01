import { describe, expect, it } from "vitest";
import { createSession, guardedToolCall, handleMessage } from "@/lib/atf/mcp/server";

describe("MCP protocol surface", () => {
  it("responds to initialize with a protocol version and server info", async () => {
    const session = await createSession();
    const response = (await handleMessage(session, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    })) as { result: { protocolVersion: string; serverInfo: { name: string } } };
    expect(response.result.protocolVersion).toBeTruthy();
    expect(response.result.serverInfo.name).toBe("agent-trust-firewall");
  });

  it("lists tools and says which capability each needs", async () => {
    const session = await createSession();
    const response = (await handleMessage(session, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    })) as { result: { tools: { name: string; description: string }[] } };
    expect(response.result.tools.length).toBeGreaterThan(0);
    for (const tool of response.result.tools) {
      expect(tool.description).toContain("Agent Trust Firewall");
    }
  });

  it("returns no reply to a notification", async () => {
    const session = await createSession();
    expect(
      await handleMessage(session, {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    ).toBeNull();
  });

  it("rejects an unknown method with a JSON-RPC error", async () => {
    const session = await createSession();
    const response = (await handleMessage(session, {
      jsonrpc: "2.0",
      id: 3,
      method: "does/not/exist",
    })) as { error: { code: number } };
    expect(response.error.code).toBe(-32601);
  });

  it("rejects a tools/call with no tool name", async () => {
    const session = await createSession();
    const response = (await handleMessage(session, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {},
    })) as { error: { code: number } };
    expect(response.error.code).toBe(-32602);
  });
});

describe("MCP interception happens before execution", () => {
  it("runs a tool the agent is authorised for", async () => {
    const session = await createSession(["search:query"]);
    const result = await guardedToolCall(session, "search.query", { q: "hello" });
    expect(result.isError).toBe(false);
    const payload = JSON.parse(result.content[0]!.text) as { verdict: string };
    expect(payload.verdict).not.toBe("BLOCK");
  });

  it("blocks a tool the agent has no capability for, and does not run it", async () => {
    // This session holds only search:query — payments.charge is out of reach.
    const session = await createSession(["search:query"]);
    const result = await guardedToolCall(session, "payments.charge", {
      amountMinor: 100000,
      currency: "USD",
    });
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0]!.text) as {
      blockedBy: string;
      verdict: string;
      violations: { rule: string }[];
    };
    expect(payload.blockedBy).toBe("agent-trust-firewall");
    expect(payload.verdict).toBe("BLOCK");
    expect(payload.violations.length).toBeGreaterThan(0);
    // The upstream tool's success shape never appears in a blocked response.
    expect(result.content[0]!.text).not.toContain('"charged"');
  });

  it("refuses an unknown tool", async () => {
    const session = await createSession();
    const result = await guardedToolCall(session, "not.a.tool", {});
    expect(result.isError).toBe(true);
  });

  it("writes an audit record for every intercepted MCP call", async () => {
    const session = await createSession(["search:query"]);
    await guardedToolCall(session, "search.query", { q: "one" });
    await guardedToolCall(session, "payments.charge", { amountMinor: 1, currency: "USD" });
    expect(await session.store.auditLength()).toBe(2);
  });

  it("uses a fresh challenge per call, so MCP traffic cannot be replayed either", async () => {
    const session = await createSession(["search:query"]);
    const a = await guardedToolCall(session, "search.query", { q: "x" });
    const b = await guardedToolCall(session, "search.query", { q: "x" });
    expect(a.isError).toBe(false);
    expect(b.isError).toBe(false);
    const records = await session.store.listAudit(10);
    expect(records[0]!.hash).not.toBe(records[1]!.hash);
  });
});
