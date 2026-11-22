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

const PROTOCOL_VERSION = "2025-06-18";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface ToolDefinition {
  name: string;
  description: string;
  /** the capability an agent must hold to invoke it */
  capability: string;
  destination: string;
  inputSchema: Record<string, unknown>;
  run: (args: Record<string, unknown>) => Promise<unknown>;
}

/**
 * The tools this server fronts. In a deployment these would proxy to real
 * upstreams; what matters here is that `run` is only ever reached by a call the
 * firewall allowed.
 */
const TOOLS: ToolDefinition[] = [
  {
    name: "search.query",
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
}

/**
 * Create a session for the connecting agent. In production the agent would
 * enrol out of band and hold its own key; for a runnable server we mint one and
 * enrol it so the protocol path can be exercised end to end.
 */
export async function createSession(
  capabilities: string[] = ["search:query", "storage:read"],
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

  return { store, agentId, signingSecretKey: signing.secretKey, capabilities };
}

/** Route one tool call through the firewall. Returns the MCP result content. */
export async function guardedToolCall(
  session: McpSession,
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: { type: "text"; text: string }[]; isError: boolean }> {
  const tool = TOOLS.find((t) => t.name === name);
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
      tool: tool.name,
      destination: tool.destination,
      capability: tool.capability,
      args,
      nonce,
    },
  );

  const decision = await decide(session.store, call, {
    config: DEFAULT_RISK_CONFIG,
  });

  if (decision.verdict === "BLOCK") {
    // The upstream tool is never invoked. This return happens instead of it.
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              blockedBy: "agent-trust-firewall",
              verdict: decision.verdict,
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
        tools: TOOLS.map((tool) => ({
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
async function main(): Promise<void> {
  const session = await createSession();
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
}

// Only run the transport when executed directly, not when imported by a test.
if (process.argv[1]?.endsWith("server.ts")) {
  void main();
}
