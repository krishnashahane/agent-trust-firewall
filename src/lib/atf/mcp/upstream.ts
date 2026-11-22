/**
 * A client for a real upstream MCP server, spoken to over stdio.
 *
 * ATF launches the server the operator names, performs the MCP handshake, and
 * forwards only the calls the firewall allowed. The command comes from the
 * operator's configuration and is spawned without a shell, so no argument is
 * ever interpreted by one.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

export const PROTOCOL_VERSION = "2025-06-18";

export interface UpstreamTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface McpToolResult {
  content: { type: string; [key: string]: unknown }[];
  isError?: boolean;
  [key: string]: unknown;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const MAX_TOOL_PAGES = 20;

export class UpstreamClient {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private closed: Error | null = null;
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly timeoutMs: number;

  // Plain fields rather than parameter properties: `npm run mcp` runs this file
  // with Node's type stripping, which does not support them.
  private constructor(child: ChildProcessWithoutNullStreams, timeoutMs: number) {
    this.child = child;
    this.timeoutMs = timeoutMs;
    const lines = createInterface({ input: child.stdout, terminal: false });
    lines.on("line", (line) => this.receive(line));
    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(`[upstream] ${chunk.toString()}`);
    });
    child.on("exit", (code) => this.fail(new Error(`upstream MCP server exited (code ${code})`)));
    child.on("error", (error) => this.fail(error));
  }

  /** Launch the upstream server and complete the MCP handshake. */
  static async start(
    command: readonly string[],
    opts: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
  ): Promise<UpstreamClient> {
    const [program, ...args] = command;
    if (!program) throw new Error("upstream command is empty");
    const child = spawn(program, args, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      env: opts.env ?? process.env,
    });
    const client = new UpstreamClient(child, opts.timeoutMs ?? 30_000);
    await client.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "agent-trust-firewall", version: "1.0.0" },
    });
    client.notify("notifications/initialized");
    return client;
  }

  async listTools(): Promise<UpstreamTool[]> {
    const tools: UpstreamTool[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_TOOL_PAGES; page++) {
      const result = (await this.request("tools/list", cursor ? { cursor } : {})) as {
        tools?: UpstreamTool[];
        nextCursor?: string;
      };
      tools.push(...(result.tools ?? []));
      if (!result.nextCursor) break;
      cursor = result.nextCursor;
    }
    return tools;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
    return (await this.request("tools/call", { name, arguments: args })) as McpToolResult;
  }

  request(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    if (this.closed) return Promise.reject(this.closed);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`upstream did not answer ${method} within ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  notify(method: string, params: Record<string, unknown> = {}): void {
    if (this.closed) return;
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  close(): void {
    this.fail(new Error("upstream client closed"));
    this.child.kill();
  }

  private receive(line: string): void {
    let message: { id?: unknown; result?: unknown; error?: { message?: string } };
    try {
      message = JSON.parse(line) as typeof message;
    } catch {
      return; // stray non-protocol output from the upstream
    }
    if (typeof message.id !== "number") return; // notifications and server requests
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) {
      pending.reject(new Error(message.error.message ?? "upstream returned an error"));
    } else {
      pending.resolve(message.result);
    }
  }

  private fail(error: Error): void {
    if (this.closed) return;
    this.closed = error;
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      this.pending.delete(id);
    }
  }
}
