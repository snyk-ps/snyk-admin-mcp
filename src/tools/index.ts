/**
 * The tool registry: every tool this server exposes, in the order `tools/list` returns them,
 * and the dispatcher every `tools/call` goes through. To add a tool, define it with
 * `defineTool` in its area's file and add it to `TOOLS` below.
 *
 * Every mutating tool routes through `runMutationTool` (mutation.ts) for the shared
 * dry-run/approve/apply flow, so the approval-token binding lives in one place rather than
 * being reimplemented per tool.
 */
import type { SnykApiConfig } from "../snyk/types.js";
import type { ToolResult } from "../mutation.js";
import { type Tool, toInputSchema } from "./types.js";
import { cloneIntegration, copyOrgSettings, createOrganization, listIntegrations, listOrgs, listProjects } from "./orgs.js";
import { addProjectTags, moveProjects, removeProjectTags } from "./projects.js";
import { searchAuditLogs } from "./audit.js";
import { getAsset, listAssetProjects, listRelatedAssets, searchAssets, updateAssets } from "./assets.js";
import { createCollection, listCollectionProjects, listCollections, updateCollection } from "./collections.js";

export const TOOLS: readonly Tool[] = [
  copyOrgSettings,
  cloneIntegration,
  addProjectTags,
  removeProjectTags,
  moveProjects,
  createOrganization,
  listOrgs,
  listIntegrations,
  listProjects,
  searchAuditLogs,
  searchAssets,
  getAsset,
  listAssetProjects,
  listRelatedAssets,
  updateAssets,
  listCollections,
  listCollectionProjects,
  createCollection,
  updateCollection,
];

const toolsByName = new Map(TOOLS.map((t) => [t.name, t]));
if (toolsByName.size !== TOOLS.length) throw new Error("Two tools in TOOLS share a name");

/** The catalog returned by `tools/list`. */
export function listTools() {
  return TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: toInputSchema(t.schema),
    annotations: t.annotations,
  }));
}

/**
 * Run one `tools/call`. This is the single error boundary for every tool: any thrown error
 * (invalid arguments, a failed API call, a missing token) becomes a normal `isError: true`
 * result instead of an unhandled rejection. `getConfig` is called inside it for that reason.
 */
export async function handleToolCall(name: string, args: unknown, getConfig: () => SnykApiConfig): Promise<ToolResult> {
  try {
    const config = getConfig();
    const tool = toolsByName.get(name);
    if (!tool) return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    return await tool.run(args, config);
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}
