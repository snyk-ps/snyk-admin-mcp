/**
 * The tool registry: every tool this server exposes, in the order `tools/list` returns them,
 * and the dispatcher every `tools/call` goes through. To add a tool, define it with
 * `defineTool` in its area's file and add it to `TOOLS` below.
 *
 * Every mutating tool routes through `runMutationTool` (mutation.ts) for the shared
 * dry-run/approve/apply flow, so the approval-token binding lives in one place rather than
 * being reimplemented per tool.
 */
import { z } from "zod";
import type { SnykApiConfig } from "../snyk/types.js";
import { type ToolCallContext, type ToolResult, withToolCallContext } from "../mutation.js";
import { type Tool, toInputSchema } from "./types.js";
import { cloneIntegration, copyOrgSettings, createOrganization, listIntegrations, listOrgs, listProjects } from "./orgs.js";
import { addProjectTags, listProjectSettings, moveProjects, removeProjectTags, updateProjects } from "./projects.js";
import { listAppInstalls, listBrokerConnections, listServiceAccounts } from "./security.js";
import { listInvites, listMembers, listUserAccess } from "./members.js";
import { listIntegrationSettings, updateIntegrationSettings } from "./integrations.js";
import { copyIgnorePolicies, listIgnorePolicies } from "./policies.js";
import { searchAuditLogs } from "./audit.js";
import { getAsset, listAssetProjects, listRelatedAssets, searchAssets, updateAssets } from "./assets.js";
import { getInventoryAssetCounts, listInventoryAssets, listInventoryFields, updateInventoryAssets } from "./inventory.js";
import { createCollection, listCollectionProjects, listCollections, updateCollection } from "./collections.js";

export const TOOLS: readonly Tool[] = [
  copyOrgSettings,
  cloneIntegration,
  updateIntegrationSettings,
  addProjectTags,
  removeProjectTags,
  moveProjects,
  updateProjects,
  createOrganization,
  listOrgs,
  listIntegrations,
  listIntegrationSettings,
  listProjects,
  listProjectSettings,
  listMembers,
  listUserAccess,
  listInvites,
  listServiceAccounts,
  listAppInstalls,
  listBrokerConnections,
  listIgnorePolicies,
  copyIgnorePolicies,
  searchAuditLogs,
  searchAssets,
  getAsset,
  listAssetProjects,
  listRelatedAssets,
  updateAssets,
  listInventoryAssets,
  getInventoryAssetCounts,
  listInventoryFields,
  updateInventoryAssets,
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
 * Replace "Invalid key in record" / "Invalid element" wrapper issues with the issues they
 * wrap, so the schema's own message (e.g. "Tag keys must be 1-30 characters…") is what the
 * caller reads, at the full path.
 */
function unwrapIssues(issues: readonly z.core.$ZodIssue[], prefix: PropertyKey[] = []): z.core.$ZodIssue[] {
  return issues.flatMap((issue) => {
    const path = [...prefix, ...issue.path];
    if ((issue.code === "invalid_key" || issue.code === "invalid_element") && issue.issues.length) {
      return unwrapIssues(issue.issues, path);
    }
    return [{ ...issue, path }];
  });
}

/**
 * Run one `tools/call`. This is the single error boundary for every tool: any thrown error
 * (invalid arguments, a failed API call, a missing token) becomes a normal `isError: true`
 * result instead of an unhandled rejection. `getConfig` is called inside it for that reason.
 */
export async function handleToolCall(name: string, args: unknown, getConfig: () => SnykApiConfig, ctx: ToolCallContext = {}): Promise<ToolResult> {
  try {
    const config = getConfig();
    const tool = toolsByName.get(name);
    if (!tool) return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    return await withToolCallContext(ctx, () => tool.run(args, config));
  } catch (err) {
    // Invalid arguments: one readable line per problem ("✖ message → at field") instead of the
    // raw JSON array of Zod issues, which is what err.message holds.
    if (err instanceof z.ZodError) {
      return { content: [{ type: "text", text: `Invalid arguments for ${name}:\n${z.prettifyError(new z.ZodError(unwrapIssues(err.issues)))}` }], isError: true };
    }
    return {
      content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}
