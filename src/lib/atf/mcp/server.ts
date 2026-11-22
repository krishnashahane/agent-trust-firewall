/**
 * The MCP interception layer.
 *
 * A real Model Context Protocol server, speaking JSON-RPC 2.0 over stdio. It
 * presents a set of tools to an agent, and every `tools/call` is routed through
 * the same `decide()` path the HTTP gateway uses. A blocked call returns a
 * structured refusal and the upstream tool is never invoked — interception
 * happens at the protocol layer, before execution, which is the whole claim.
 *
 * Run it with:  npm run mcp
 *
 * Two modes:
 *  - Demo (default): fronts three built-in tools so the path can be tried.
 *  - Proxy: set ATF_MCP_UPSTREAM to a JSON array naming a real MCP server, e.g.
 *      ATF_MCP_UPSTREAM='["npx","-y","@modelcontextprotocol/server-filesystem","/tmp"]'
 *    ATF launches it, exposes its tools unchanged, and forwards a call only
 *    after the firewall allows it. Upstream tool `read_file` needs capability
 *    `mcp:read_file`; grant them with ATF_MCP_GRANTS="mcp:read_file,mcp:list_directory"
 *    or `mcp:*`. Nothing is granted by default.
 *
 * The protocol is implemented directly rather than through an SDK: it is a small
 *, stable JSON-RPC surface, and a security component with fewer dependencies is
 * a security component with a smaller attack surface.
 */
import { createInterface } from "node:readline";
import { MemoryStore } from "../store/memory.ts";
import { registerAgent } from "../identity/registry.ts";
import { capabilityRoot } from "../identity/merkle.ts";
import { issueChallenge } from "../identity/nonce.ts";
import { decide } from "../interceptor/decide.ts";
import { DEFAULT_RISK_CONFIG } from "../risk/config.ts";
import { signCall } from "../client.ts";
import { generateKeyPair } from "../identity/schnorr.ts";
import { generateEncryptionKeyPair } from "../crypto/e2ee.ts";
import type { Store } from "../store/port.ts";
import { PROTOCOL_VERSION, UpstreamClient, type McpToolResult, type UpstreamTool } from "./upstream.ts";


interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface ToolDefinition {
  /** the name the MCP client sees and calls */
  name: string;
  /** the tool id the firewall scores, `namespace.action` */
  tool: string;
  description: string;
  /** the capability an agent must hold to invoke it */
  capability: string;
  destination: string;
  inputSchema: Record<string, unknown>;
  run: (args: Record<string, unknown>) => Promise<unknown>;
  /** set for proxied tools: the upstream's own result is returned verbatim */
  forward?: (args: Record<string, unknown>) => Promise<McpToolResult>;
}

/**
 * The tools this server fronts. In a deployment these would proxy to real
 * upstreams; what matters here is that `run` is only ever reached by a call the
 * firewall allowed.
 */
export const DEMO_TOOLS: ToolDefinition[] = [
  {
    name: "search.query",
    tool: "search.query",
    description: "Search the internal knowledge base.",
    capability: "search:query",
    destination: "api.search.internal",
    inputSchema: {
      type: "object",
      properties: { q: { type: "string" }, limit: { type: "number" } },
      required: ["q"],
    },
    run: async (args) => ({ results: [], echo: args["q"] }),
  },
  {
    name: "payments.charge",
    tool: "payments.charge",
    description: "Charge a customer's stored payment method.",
    capability: "payments:charge",
    destination: "api.payments.internal",
    inputSchema: {
      type: "object",
      properties: {
        amountMinor: { type: "number" },
        currency: { type: "string" },
        reference: { type: "string" },
      },
      required: ["amountMinor", "currency"],
    },
    run: async (args) => ({ charged: true, amountMinor: args["amountMinor"] }),
  },
  {
    name: "storage.read",
    tool: "storage.read",
    description: "Read an object from internal storage.",
    capability: "storage:read",
    destination: "api.storage.internal",
    inputSchema: {
      type: "object",
      properties: { key: { type: "string" } },
      required: ["key"],
    },
    run: async (args) => ({ key: args["key"], bytes: 0 }),
  },
];

export interface McpSession {
  store: Store;
  agentId: string;
  signingSecretKey: string;
  capabilities: string[];
  tools: ToolDefinition[];
}

/**
 * Wrap an upstream server's tools. Each needs `mcp:<name>`, scored as the tool
 * `mcp.<name>`, so one capability authorises exactly one upstream tool and
 * `mcp:*` authorises all of them.
 */
export function proxiedTools(
  upstream: Pick<UpstreamClient, "callTool">,
  tools: readonly UpstreamTool[],
  destination = "mcp-upstream",
): ToolDefinition[] {
  return tools.map((tool) => ({
    name: tool.name,
    tool: `mcp.${tool.name}`,
    description: tool.description ?? "",
    capability: `mcp:${tool.name}`,
    destination,
    inputSchema: tool.inputSchema ?? { type: "object" },
    run: async () => undefined,
    forward: (args) => upstream.callTool(tool.name, args),
  }));
}

/**
 * Create a session for the connecting agent. In production the agent would
 * enrol out of band and hold its own key; for a runnable server we mint one and
 * enrol it so the protocol path can be exercised end to end.
 */
export async function createSession(
  capabilities: string[] = ["search:query", "storage:read"],
  tools: ToolDefinition[] = DEMO_TOOLS,
): Promise<McpSession> {
  const store = new MemoryStore();
  const signing = generateKeyPair();
  const encryption = generateEncryptionKeyPair();
  const agentId = "mcp-client";

  await registerAgent(store, {
    agentId,
    displayName: "MCP Client",
    signingPublicKey: signing.publicKey,
    encryptionPublicKey: encryption.publicKey,
    capabilityRoot: capabilityRoot(capabilities),
  });

  return { store, agentId, signingSecretKey: signing.secretKey, capabilities, tools };
}

export interface GuardedResult {
  content: { type: "text"; text: string }[];
  isError: boolean;
  /** the firewall's verdict on a proxied call, beside the upstream's own result */
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Route one tool call through the firewall. Returns the MCP result content. */
export async function guardedToolCall(
  session: McpSession,
  name: string,
  args: Record<string, unknown>,
): Promise<GuardedResult> {
  const tool = session.tools.find((t) => t.name === name);
  if (!tool) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }

  const { nonce } = await issueChallenge(session.store, session.agentId);
  const call = signCall(
    {
      agentId: session.agentId,
      signingSecretKey: session.signingSecretKey,
      capabilities: session.capabilities,
    },
    {
      tool: tool.tool,
      destination: tool.destination,
      capability: tool.capability,
      args,
      nonce,
    },
  );

  const decision = await decide(session.store, call, {
    config: DEFAULT_RISK_CONFIG,
  });

  // FLAG means "hold for a human". Over stdio there is no human to approve it,
  // so a flagged call is held exactly like a blocked one, and says which.
  if (decision.verdict !== "ALLOW") {
    // The upstream tool is never invoked. This return happens instead of it.
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              blockedBy: "agent-trust-firewall",
              verdict: decision.verdict,
              ...(decision.verdict === "FLAG"
                ? { held: "flagged for human review; not executed" }
                : {}),
              score: decision.risk.score,
              reason: decision.explanation,
              violations: decision.violations,
              auditId: decision.auditId,
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  if (tool.forward) {
    const upstream = await tool.forward(args);
    return {
      ...upstream,
      content: upstream.content as { type: "text"; text: string }[],
      isError: upstream.isError === true,
      _meta: {
        "agent-trust-firewall": {
          verdict: decision.verdict,
          score: decision.risk.score,
          auditId: decision.auditId,
        },
      },
    };
  }

  const result = await tool.run(args);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            verdict: decision.verdict,
            score: decision.risk.score,
            auditId: decision.auditId,
            result,
          },
          null,
          2,
        ),
      },
    ],
    isError: false,
  };
}

/** Handle one JSON-RPC message. Exported so tests can drive it directly. */
export async function handleMessage(
  session: McpSession,
  message: JsonRpcRequest,
): Promise<object | null> {
  const reply = (result: unknown) => ({
    jsonrpc: "2.0" as const,
    id: message.id ?? null,
    result,
  });
  const error = (code: number, msg: string) => ({
    jsonrpc: "2.0" as const,
    id: message.id ?? null,
    error: { code, message: msg },
  });

  switch (message.method) {
    case "initialize":
      return reply({
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "agent-trust-firewall", version: "1.0.0" },
      });

    case "notifications/initialized":
      // Notifications carry no id and take no reply.
      return null;

    case "tools/list":
      return reply({
        tools: session.tools.map((tool) => ({
          name: tool.name,
          description: `${tool.description} (guarded by Agent Trust Firewall; requires ${tool.capability})`,
          inputSchema: tool.inputSchema,
        })),
      });

    case "tools/call": {
      const params = message.params ?? {};
      const name = params["name"];
      const args = params["arguments"];
      if (typeof name !== "string") return error(-32602, "tool name is required");
      if (args !== undefined && (typeof args !== "object" || args === null)) {
        return error(-32602, "arguments must be an object");
      }
      return reply(
        await guardedToolCall(session, name, (args ?? {}) as Record<string, unknown>),
      );
    }

    case "ping":
      return reply({});

    default:
      return message.id === undefined ? null : error(-32601, "method not found");
  }
}

/** stdio transport: one JSON-RPC message per line. */
/** Parse ATF_MCP_UPSTREAM: a JSON array of strings, the command and its args. */
export function parseUpstreamCommand(raw: string | undefined): string[] | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('ATF_MCP_UPSTREAM must be a JSON array, e.g. ["npx","-y","some-mcp-server"]');
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed.every((p) => typeof p === "string")) {
    throw new Error("ATF_MCP_UPSTREAM must be a non-empty JSON array of strings");
  }
  return parsed as string[];
}

export const parseGrants = (raw: string | undefined): string[] =>
  (raw ?? "")
    .split(",")
    .map((g) => g.trim())
    .filter(Boolean);

async function main(): Promise<void> {
  const command = parseUpstreamCommand(process.env.ATF_MCP_UPSTREAM);
  let session: McpSession;
  let shutdown = () => {};
  if (command) {
    const upstream = await UpstreamClient.start(command);
    const tools = proxiedTools(upstream, await upstream.listTools());
    const grants = parseGrants(process.env.ATF_MCP_GRANTS);
    if (grants.length === 0) {
      console.error(
        "[atf-mcp] ATF_MCP_GRANTS is empty: every upstream tool call will be blocked. " +
          'Grant tools with e.g. ATF_MCP_GRANTS="mcp:read_file" or "mcp:*".',
      );
    }
    // The session's Merkle tree needs at least one leaf; a placeholder grants nothing.
    session = await createSession(grants.length > 0 ? grants : ["none:none"], tools);
    console.error(`[atf-mcp] proxying ${tools.length} upstream tool(s) through the firewall`);
    shutdown = () => upstream.close();
  } else {
    session = await createSession();
  }
  const rl = createInterface({ input: process.stdin, terminal: false });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let message: JsonRpcRequest;
    try {
      message = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "parse error" },
        }) + "\n",
      );
      continue;
    }

    try {
      const response = await handleMessage(session, message);
      if (response) process.stdout.write(JSON.stringify(response) + "\n");
    } catch (caught) {
      // Never leak an internal error message to the client.
      console.error("[atf-mcp]", caught);
      if (message.id !== undefined) {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            error: { code: -32603, message: "internal error" },
          }) + "\n",
        );
      }
    }
  }
  // The client hung up: stop the upstream too, or its process keeps us alive.
  shutdown();
}

// Only run the transport when executed directly, not when imported by a test.
if (process.argv[1]?.endsWith("server.ts")) {
  void main();
}
