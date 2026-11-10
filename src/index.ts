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

// Load .env from project root (one level up from dist/). `quiet` and `debug` are set
// explicitly because stdout is the MCP protocol channel: dotenv 18 reads DOTENV_CONFIG_DEBUG
// from the environment and, if it's set, prints debug lines to stdout ahead of the first
// JSON-RPC message, which breaks the client connection. Explicit options take precedence
// over those env vars. `quiet` also drops its "injected env" line from stderr.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadEnv({ path: path.join(__dirname, "..", ".env"), quiet: true, debug: false });

/** Read from package.json so the version clients see in the MCP handshake can't drift from the release. */
const { version: SERVER_VERSION } = JSON.parse(
  readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
) as { version: string };

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { SnykApiConfig, SnykRegion } from "./snyk/types.js";
import { handleToolCall, listTools } from "./tools/index.js";
import type { ConfirmResult } from "./mutation.js";

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

/**
 * SNYK_ADMIN_CONFIRM=off turns the confirmation prompt off (for a client that advertises
 * elicitation but can't actually show it). Anything else, or unset, means "ask when the
 * client supports it".
 */
const CONFIRM_OFF = (process.env.SNYK_ADMIN_CONFIRM ?? "").trim().toLowerCase() === "off";

/** How long to wait for the person to answer; the approval token itself is valid for 10 minutes. */
const CONFIRM_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Before an apply, ask the person through the MCP client (elicitation, a form with one
 * checkbox) whether to go ahead. Only a submitted form with the box ticked counts as yes.
 * Clients that don't support elicitation get "unavailable", so the token flow decides alone.
 *
 * The prompt is tied to the tool call's signal: if the client cancels or times out the call,
 * the prompt is withdrawn and nothing is applied (the client would never see the result).
 * `confirm` isn't a required field, so a client that leaves an unticked box out of its answer
 * reads as a no rather than failing the SDK's schema check.
 */
function confirmApplyFor(signal: AbortSignal) {
  return async ({ toolName, summary }: { toolName: string; summary: string }): Promise<ConfirmResult> => {
    if (CONFIRM_OFF || !server.getClientCapabilities()?.elicitation?.form) return "unavailable";
    const result = await server.elicitInput(
      {
        message: `Snyk Admin MCP will make this change in Snyk with ${toolName} if you confirm:\n\n${summary}`,
        requestedSchema: {
          type: "object",
          properties: {
            confirm: { type: "boolean", title: "Apply this change", description: "Tick and submit to make this change in Snyk now. Decline to cancel it.", default: false },
          },
        },
      },
      { timeout: CONFIRM_TIMEOUT_MS, signal }
    );
    return result.action === "accept" && result.content?.confirm === true ? "confirmed" : "declined";
  };
}

// The MCP SDK's expected return type for tools/call is a large union that a plain
// ToolResult value doesn't structurally satisfy when passed through directly (a TypeScript
// quirk with how it checks large unions against a non-literal object) — rebuilding a fresh
// literal here from `result`'s fields is what makes this typecheck.
server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  const result = await handleToolCall(request.params.name, request.params.arguments, getConfig, { confirm: confirmApplyFor(extra.signal), signal: extra.signal });
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
