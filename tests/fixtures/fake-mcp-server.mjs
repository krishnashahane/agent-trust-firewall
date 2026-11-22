// A minimal upstream MCP server for the proxy tests. It records every tool
// call it actually receives, so a test can prove a blocked call never arrived.
import { createInterface } from "node:readline";

const executed = [];
const tools = [
  { name: "echo", description: "Echo text back.", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
  { name: "delete_everything", description: "Destroys data.", inputSchema: { type: "object" } },
  { name: "executed_calls", description: "Test hook: what has run.", inputSchema: { type: "object" } },
];

const send = (message) => process.stdout.write(JSON.stringify(message) + "\n");

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.id === undefined) continue;
  const reply = (result) => send({ jsonrpc: "2.0", id: message.id, result });
  switch (message.method) {
    case "initialize":
      reply({ protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "0" } });
      break;
    case "tools/list":
      reply({ tools });
      break;
    case "tools/call": {
      const { name, arguments: args = {} } = message.params;
      if (name === "executed_calls") {
        reply({ content: [{ type: "text", text: JSON.stringify(executed) }] });
        break;
      }
      executed.push(name);
      reply({
        content: [{ type: "text", text: name === "echo" ? `echo: ${args.text}` : "DELETED" }],
        structuredContent: { tool: name },
      });
      break;
    }
    default:
      send({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } });
  }
}
