#!/usr/bin/env node
/**
 * Snyk Admin MCP server entry point: loads config, builds the MCP server, and connects it
 * over stdio. The tools themselves live in src/tools/ — `tools/index.ts` is the registry
 * (every tool, in catalog order, plus the dispatcher), and each area has its own file
 * (orgs, projects, audit, assets, collections). The Snyk API clients are in src/snyk/.
 */
import path from "path";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { config as loadEnv } from "dotenv";

// Load .env from project root (one level up from dist/)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadEnv({ path: path.join(__dirname, "..", ".env") });

/** Read from package.json so the version clients see in the MCP handshake can't drift from the release. */
const { version: SERVER_VERSION } = JSON.parse(
  readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
) as { version: string };

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { SnykApiConfig, SnykRegion } from "./snyk/types.js";
import { handleToolCall, listTools } from "./tools/index.js";

const SNYK_TOKEN = process.env.SNYK_API_TOKEN ?? process.env.SNYK_TOKEN ?? "";
const SNYK_REGION = (process.env.SNYK_API_REGION ?? "us-01") as SnykRegion;

/** Build the API config from env vars, read once per tool call. Throws if no token is configured. */
function getConfig(): SnykApiConfig {
  if (!SNYK_TOKEN) throw new Error("SNYK_API_TOKEN or SNYK_TOKEN environment variable is required");
  return { token: SNYK_TOKEN, region: SNYK_REGION };
}

const server = new Server(
  {
    name: "snyk-admin-mcp",
    version: SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: listTools() }));

// The MCP SDK's expected return type for tools/call is a large union that a plain
// ToolResult value doesn't structurally satisfy when passed through directly (a TypeScript
// quirk with how it checks large unions against a non-literal object) — rebuilding a fresh
// literal here from `result`'s fields is what makes this typecheck.
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await handleToolCall(request.params.name, request.params.arguments, getConfig);
  return { content: result.content, isError: result.isError };
});

/** Start the server over stdio — the standard MCP transport for a subprocess-launched server. */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Snyk Admin MCP server running on stdio.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
