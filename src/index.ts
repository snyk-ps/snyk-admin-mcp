#!/usr/bin/env node
import path from "path";
import { fileURLToPath } from "url";
import { config as loadEnv } from "dotenv";

// Load .env from project root (one level up from dist/)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadEnv({ path: path.join(__dirname, "..", ".env") });

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import * as rest from "./snyk/rest.js";
import * as v1 from "./snyk/v1.js";
import { sanitizePathSegment, type SnykApiConfig } from "./snyk/types.js";
import { runMutationTool, type ToolResult } from "./mutation.js";

const SNYK_TOKEN = process.env.SNYK_API_TOKEN ?? process.env.SNYK_TOKEN ?? "";
const SNYK_REGION = (process.env.SNYK_API_REGION ?? "global") as "global" | "eu" | "us" | "au";

function getConfig(): SnykApiConfig {
  if (!SNYK_TOKEN) throw new Error("SNYK_API_TOKEN or SNYK_TOKEN environment variable is required");
  return { token: SNYK_TOKEN, region: SNYK_REGION };
}

/** Format org_id as "name (id)" when name is available. */
async function formatOrgId(config: SnykApiConfig, orgId: string): Promise<string> {
  const name = await rest.getOrgName(config, orgId);
  return name ? `${name} (${orgId})` : orgId;
}

/** Format integration_id as "type (id)" when type is available. */
async function formatIntegrationId(config: SnykApiConfig, orgId: string, integrationId: string): Promise<string> {
  const typeName = await v1.getIntegrationTypeName(config, orgId, integrationId);
  return typeName ? `${typeName} (${integrationId})` : integrationId;
}

const server = new Server(
  {
    name: "snyk-admin-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// --- Copy org settings ---
const CopySettingsArgsSchema = z.object({
  source_org_id: z.string().describe("Source organization ID (to copy from)"),
  target_org_id: z.string().describe("Target organization ID (to copy to)"),
  dry_run: z.boolean().default(true).describe("If true, only return a plan; no changes. Set false and provide approval_token to apply."),
  approval_token: z.string().optional().describe("Required when dry_run is false; use the token returned from a prior dry run."),
});

// --- Clone integration ---
const CloneIntegrationArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID that has the integration"),
  integration_id: z.string().describe("Integration ID to clone"),
  target_org_id: z.string().describe("Organization ID to clone the integration into"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Add project tags (V1 project tags). Not a real batch API — one HTTP call per project x tag. ---
const AddProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to apply tags to"),
  tags: z.array(z.object({
    key: z.string(),
    value: z.string().optional(),
  })).describe("Tags to add (key or key:value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Remove project tags (V1 project tags). Not a real batch API — one HTTP call per project x key. ---
const RemoveProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to remove tags from"),
  tag_keys: z.array(z.string()).describe("Tag keys to remove (removal is by key only, no value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Create organization (V1) ---
const CreateOrganizationArgsSchema = z.object({
  name: z.string().describe("Name of the new organization"),
  group_id: z.string().optional().describe("Group ID to create the org under (required for Enterprise/group accounts)"),
  source_org_id: z.string().optional().describe("Optional template org ID to copy settings from"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Asset API (Early Access): search, get, relationships, update ---

/** Recursive filter node for asset search. */
type AssetSearchAttributesInput = {
  attribute?: string;
  operator: string;
  values: Array<string | number | boolean | AssetSearchAttributesInput>;
};
const AssetSearchAttributesSchema: z.ZodType<AssetSearchAttributesInput> = z.lazy(() =>
  z.object({
    attribute: z.string().optional().describe("Asset attribute to filter on (e.g. name, type, class, labels, tags.<key>). Omit when using a logical operator (and/or)."),
    operator: z.string().describe("Operator: and, or, equal, not_equal, contains, not_contains, starts_with, ends_with, in, not_in, greater_than, lower_than, equal_or_greater_than, equal_or_lower_than."),
    values: z.array(z.union([z.string(), z.number(), z.boolean(), AssetSearchAttributesSchema])).describe("Values, or nested filter objects when using and/or."),
  })
);

const SearchAssetsArgsSchema = z.object({
  group_id: z.string().describe("Group ID to search assets in"),
  query: z.object({ attributes: AssetSearchAttributesSchema }).optional().describe("Optional filter. Omit to list all assets."),
  limit: z.number().optional().describe("Records to return (10-100)"),
  starting_after: z.string().optional().describe("Cursor: return records after this cursor"),
  ending_before: z.string().optional().describe("Cursor: return records before this cursor"),
});

const GetAssetArgsSchema = z.object({
  group_id: z.string().describe("Group ID that owns the asset"),
  asset_id: z.string().describe("Asset ID (UUID)"),
});

const ListAssetProjectsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional(),
  ending_before: z.string().optional(),
});

const ListRelatedAssetsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  type: z.enum(["repository", "package", "image"]).optional(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional(),
  ending_before: z.string().optional(),
});

// --- Update assets (Asset API). The API has no batch endpoint: one PATCH per asset. ---
const UpdateAssetsArgsSchema = z.object({
  group_id: z.string().describe("Group ID that owns the assets"),
  asset_ids: z.array(z.string()).min(1).max(200).describe("One or more asset IDs (get these from snyk_search_assets)"),
  type: z.enum(["repository", "image", "package"]).default("repository").describe("Asset type — all asset_ids must be of this type"),
  class: z.object({
    display_name: z.enum(["A", "B", "C", "D"]).optional(),
    rank: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
    locked: z.boolean().optional(),
  }).optional().describe("Set asset class by display_name (A-D) or rank (1-4)."),
  labels: z.object({
    add: z.array(z.string()).optional(),
    remove: z.array(z.string()).optional(),
  }).optional().describe("Labels to add/remove on every listed asset."),
  tags: z.object({
    add: z.record(z.string(), z.string()).optional(),
    remove: z.array(z.string()).optional(),
  }).optional().describe("Tag key-value pairs to add, and tag keys to remove, on every listed asset."),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "snyk_copy_org_settings",
      description: "Copy organization settings from a source org to a target org. Uses Snyk V1 API (org settings). Always run with dry_run=true first to get a plan and approval_token, then run with dry_run=false and approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          source_org_id: { type: "string", description: "Source organization ID (to copy from)" },
          target_org_id: { type: "string", description: "Target organization ID (to copy to)" },
          dry_run: { type: "boolean", description: "If true, only return a plan; no changes. Set false and provide approval_token to apply.", default: true },
          approval_token: { type: "string", description: "Required when dry_run is false; use the token returned from a prior dry run." },
        },
        required: ["source_org_id", "target_org_id"],
      },
    },
    {
      name: "snyk_clone_integration",
      description: "Clone an integration (with settings and credentials) from one organization to another. Uses Snyk V1 API. CLI integrations are not supported (rejected). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: {
        type: "object",
        properties: {
          source_org_id: { type: "string", description: "Organization ID that has the integration" },
          integration_id: { type: "string", description: "Integration ID to clone" },
          target_org_id: { type: "string", description: "Organization ID to clone the integration into" },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["source_org_id", "integration_id", "target_org_id"],
      },
    },
    {
      name: "snyk_add_project_tags",
      description: "Add tags to multiple projects (one V1 API call per project x tag, not a single batch request). Uses Snyk V1 API (project tags). Note: these are project tags, not asset labels — use snyk_update_assets for asset labels. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          project_ids: { type: "array", items: { type: "string" }, description: "List of project IDs to apply tags to" },
          tags: {
            type: "array",
            items: { type: "object", properties: { key: { type: "string" }, value: { type: "string" } }, required: ["key"] },
            description: "Tags to add (key or key:value)",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "project_ids", "tags"],
      },
    },
    {
      name: "snyk_remove_project_tags",
      description: "Remove tags (by key) from multiple projects (one V1 API call per project x key, not a single batch request). Uses Snyk V1 API (project tags). Removal is by key only — no value needed. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          project_ids: { type: "array", items: { type: "string" }, description: "List of project IDs to remove tags from" },
          tag_keys: { type: "array", items: { type: "string" }, description: "Tag keys to remove" },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "project_ids", "tag_keys"],
      },
    },
    {
      name: "snyk_create_organization",
      description: "Create a new Snyk organization. Uses Snyk V1 API (POST /org). Optional: group_id (required for group/Enterprise), source_org_id (copy settings from template). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Name of the new organization" },
          group_id: { type: "string", description: "Group ID to create the org under (required for Enterprise/group accounts)" },
          source_org_id: { type: "string", description: "Optional template org ID to copy settings from" },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["name"],
      },
    },
    {
      name: "snyk_list_orgs",
      description: "List organizations accessible to the token (REST API). Read-only. Supports cursor pagination and filters. Returns a `links.next` cursor for the next page.",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of results per page (API default: 10)" },
          starting_after: { type: "string", description: "Return results after this cursor (from links.next of a previous response)" },
          ending_before: { type: "string", description: "Return results before this cursor (from links.prev of a previous response)" },
          group_id: { type: "string", description: "Filter: only return orgs within this group" },
          is_personal: { type: "boolean", description: "Filter: if true, only return orgs not part of any group" },
          slug: { type: "string", description: "Filter: only return orgs whose slug exactly matches this value" },
          name: { type: "string", description: "Filter: only return orgs whose name contains this value" },
        },
      },
    },
    {
      name: "snyk_list_integrations",
      description: "List integrations for an organization (V1 API). Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
        },
        required: ["org_id"],
      },
    },
    {
      name: "snyk_list_projects",
      description: "List projects for an organization (REST API). Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
        },
        required: ["org_id"],
      },
    },
    {
      name: "snyk_search_assets",
      description: "Search assets in a group using the Asset API (REST, Early Access). POST /groups/{group_id}/assets/search. Read-only. Provide an optional filter query, or omit it to list all assets. Supports cursor pagination via limit/starting_after/ending_before.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID to search assets in" },
          query: {
            type: "object",
            description: "Optional filter. Omit to list all assets.",
            properties: {
              attributes: {
                type: "object",
                description: "Filter node. Use a single attribute filter, or a logical operator (and/or) with nested filters in values.",
                properties: {
                  attribute: { type: "string", description: "Asset attribute to filter on (e.g. name, type, class, labels, tags.<key>). Omit for logical operators." },
                  operator: { type: "string", description: "and, or, equal, not_equal, contains, not_contains, starts_with, ends_with, in, not_in, greater_than, lower_than, equal_or_greater_than, equal_or_lower_than" },
                  values: { type: "array", description: "Values, or nested filter objects when using and/or." },
                },
                required: ["operator", "values"],
              },
            },
            required: ["attributes"],
          },
          limit: { type: "number", description: "Records to return (10-100)" },
          starting_after: { type: "string", description: "Cursor: return records after this cursor" },
          ending_before: { type: "string", description: "Cursor: return records before this cursor" },
        },
        required: ["group_id"],
      },
    },
    {
      name: "snyk_get_asset",
      description: "Get a single asset by its ID within a group (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID that owns the asset" },
          asset_id: { type: "string", description: "Asset ID (UUID)" },
        },
        required: ["group_id", "asset_id"],
      },
    },
    {
      name: "snyk_list_asset_projects",
      description: "List projects related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/projects. Read-only. Cursor pagination via starting_after/ending_before.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string" },
          asset_id: { type: "string" },
          limit: { type: "number", description: "Records to return (10-100)" },
          starting_after: { type: "string", description: "Cursor: return records after this cursor" },
          ending_before: { type: "string", description: "Cursor: return records before this cursor" },
        },
        required: ["group_id", "asset_id"],
      },
    },
    {
      name: "snyk_list_related_assets",
      description: "List assets related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/assets. Read-only. Optional type filter and cursor pagination.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string" },
          asset_id: { type: "string" },
          type: { type: "string", enum: ["repository", "package", "image"], description: "Filter by asset type" },
          limit: { type: "number", description: "Records to return (10-100)" },
          starting_after: { type: "string" },
          ending_before: { type: "string" },
        },
        required: ["group_id", "asset_id"],
      },
    },
    {
      name: "snyk_update_assets",
      description: "Update class, labels, and/or tags on one or more assets (REST Asset API, Early Access). Issues one PATCH per asset — the Asset API has no batch endpoint — and reports per-asset success/failure, so a partial failure leaves earlier assets updated. Works for repository, image, and package assets; pass a single ID in asset_ids to update just one. Get asset_ids from snyk_search_assets. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID that owns the assets" },
          asset_ids: {
            type: "array",
            minItems: 1,
            maxItems: 200,
            items: { type: "string" },
            description: "One or more asset IDs (get these from snyk_search_assets)",
          },
          type: { type: "string", enum: ["repository", "image", "package"], default: "repository", description: "Asset type — all asset_ids must be of this type" },
          class: {
            type: "object",
            description: "Set asset class by display_name (A-D) or rank (1-4). If both given, rank wins.",
            properties: {
              display_name: { type: "string", enum: ["A", "B", "C", "D"] },
              rank: { type: "number", enum: [1, 2, 3, 4] },
              locked: { type: "boolean", description: "Whether the class is locked from policy changes" },
            },
          },
          labels: {
            type: "object",
            properties: {
              add: { type: "array", items: { type: "string" } },
              remove: { type: "array", items: { type: "string" } },
            },
            description: "Labels to add/remove on every listed asset",
          },
          tags: {
            type: "object",
            properties: {
              add: { type: "object", additionalProperties: { type: "string" }, description: "Tag key-value pairs to add" },
              remove: { type: "array", items: { type: "string" }, description: "Tag keys to remove" },
            },
            description: "Tags to add/remove on every listed asset",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["group_id", "asset_ids"],
      },
    },
  ],
}));

async function handleToolCall(request: CallToolRequest): Promise<ToolResult> {
  const { name, arguments: args } = request.params;
  try {
    const config = getConfig();
    if (name === "snyk_list_orgs") {
      const a = args as {
        limit?: number; starting_after?: string; ending_before?: string;
        group_id?: string; is_personal?: boolean; slug?: string; name?: string;
      } ?? {};
      const data = await rest.listOrgs(config, {
        limit: a.limit,
        starting_after: a.starting_after,
        ending_before: a.ending_before,
        group_id: a.group_id,
        is_personal: a.is_personal,
        slug: a.slug,
        name: a.name,
      });
      const lines = (data.data ?? []).map((org) => {
        const orgName = org.attributes?.name ?? "—";
        return `${orgName} (${org.id})`;
      });
      const summary = lines.length ? lines.join("\n") : "No organizations.";
      const full = {
        data: data.data?.map((org) => ({
          id: org.id,
          name: org.attributes?.name ?? null,
          slug: org.attributes?.slug ?? null,
          group_id: org.attributes?.group_id ?? null,
        })),
        pagination: {
          next: data.links?.next ?? null,
          prev: data.links?.prev ?? null,
          count: data.meta?.count ?? null,
        },
      };
      const nextHint = data.links?.next
        ? `\n\nNext page cursor: pass starting_after="${data.links.next}" to get the next page.`
        : "";
      return {
        content: [{ type: "text", text: `${summary}${nextHint}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
        isError: false,
      };
    }
    if (name === "snyk_list_integrations") {
      const org_id = (args as { org_id?: string }).org_id;
      if (!org_id) throw new Error("org_id is required");
      const data = await v1.listIntegrations(config, sanitizePathSegment(org_id, "org_id"));
      const orgName = await rest.getOrgName(config, org_id);
      const header = orgName ? `Integrations for ${orgName} (${org_id}):` : `Integrations for org ${org_id}:`;
      const lines = Object.entries(data).map(([typeName, id]) => `${typeName} (${id})`);
      const body = lines.length ? lines.join("\n") : "No integrations.";
      return {
        content: [{ type: "text", text: `${header}\n\n${body}\n\nRaw:\n${JSON.stringify(data, null, 2)}` }],
        isError: false,
      };
    }
    if (name === "snyk_list_projects") {
      const org_id = (args as { org_id?: string }).org_id;
      if (!org_id) throw new Error("org_id is required");
      const data = await rest.listProjects(config, sanitizePathSegment(org_id, "org_id"));
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_search_assets") {
      const parsed = SearchAssetsArgsSchema.parse(args);
      const data = await rest.searchAssets(config, parsed.group_id, parsed.query, {
        limit: parsed.limit,
        starting_after: parsed.starting_after,
        ending_before: parsed.ending_before,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_get_asset") {
      const parsed = GetAssetArgsSchema.parse(args);
      const data = await rest.getAsset(config, parsed.group_id, parsed.asset_id);
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_list_asset_projects") {
      const parsed = ListAssetProjectsArgsSchema.parse(args);
      const data = await rest.listAssetProjects(config, parsed.group_id, parsed.asset_id, {
        limit: parsed.limit,
        starting_after: parsed.starting_after,
        ending_before: parsed.ending_before,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_list_related_assets") {
      const parsed = ListRelatedAssetsArgsSchema.parse(args);
      const data = await rest.listRelatedAssets(config, parsed.group_id, parsed.asset_id, {
        type: parsed.type,
        limit: parsed.limit,
        starting_after: parsed.starting_after,
        ending_before: parsed.ending_before,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_create_organization") {
      const parsed = CreateOrganizationArgsSchema.parse(args);
      const resolvedGroupId = parsed.group_id ?? (await rest.getDefaultGroupId(config));
      if (!resolvedGroupId) {
        return {
          content: [{
            type: "text",
            text: "No group_id provided and none could be inferred (token may have only personal orgs or no orgs). Provide group_id explicitly, or use snyk_list_orgs to get an org's group_id from attributes.",
          }],
          isError: true,
        };
      }
      type CreateOrgPlan = { name: string; group_id: string; source_org_id?: string };
      return await runMutationTool<CreateOrgPlan>({
        action: "create_organization",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { name: parsed.name, group_id: resolvedGroupId, source_org_id: parsed.source_org_id },
        buildPlanData: () => ({ name: parsed.name, group_id: resolvedGroupId, source_org_id: parsed.source_org_id }),
        describeDryRun: async (data) => {
          const sourceOrgLabel = data.source_org_id ? ` (copying settings from ${await formatOrgId(config, data.source_org_id)})` : "";
          return `Dry run – will create organization "${data.name}" in group ${data.group_id}${sourceOrgLabel}.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const result = await v1.createOrganization(config, {
            name: data.name,
            group_id: sanitizePathSegment(data.group_id, "group_id"),
            source_org_id: data.source_org_id ? sanitizePathSegment(data.source_org_id, "source_org_id") : undefined,
          });
          const resultOrgName = (result as { name?: string }).name ?? (result as { id?: string }).id;
          return `Organization created: ${resultOrgName}. Result: ${JSON.stringify(result, null, 2)}`;
        },
      });
    }

    if (name === "snyk_copy_org_settings") {
      const parsed = CopySettingsArgsSchema.parse(args);
      type CopySettingsPlan = { source_org_id: string; target_org_id: string; settings_to_apply: Record<string, unknown> };
      return await runMutationTool<CopySettingsPlan>({
        action: "copy_org_settings",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id },
        buildPlanData: async () => ({
          source_org_id: parsed.source_org_id,
          target_org_id: parsed.target_org_id,
          settings_to_apply: await v1.getOrgSettings(config, sanitizePathSegment(parsed.source_org_id, "source_org_id")),
        }),
        describeDryRun: async (data) => {
          const sourceLabel = await formatOrgId(config, data.source_org_id);
          const targetLabel = await formatOrgId(config, data.target_org_id);
          return `Dry run – copy settings from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(data, null, 2)}\n\nNote: only requestAccess and similar editable fields will be applied (V1 org settings).`;
        },
        apply: async (data) => {
          await v1.updateOrgSettings(config, sanitizePathSegment(data.target_org_id, "target_org_id"), data.settings_to_apply);
          const targetLabel = await formatOrgId(config, data.target_org_id);
          return `Org settings copied to ${targetLabel}.`;
        },
      });
    }

    if (name === "snyk_clone_integration") {
      const parsed = CloneIntegrationArgsSchema.parse(args);
      const safeSourceOrg = sanitizePathSegment(parsed.source_org_id, "source_org_id");
      const safeIntegrationId = sanitizePathSegment(parsed.integration_id, "integration_id");
      const integrationType = await v1.getIntegrationTypeName(config, safeSourceOrg, safeIntegrationId);
      if (v1.isCliIntegrationType(integrationType)) {
        return {
          content: [{
            type: "text",
            text: "CLI integration cannot be cloned via the API; skip it when copying integrations between organizations.",
          }],
          isError: true,
        };
      }
      type CloneIntegrationPlan = { source_org_id: string; integration_id: string; target_org_id: string };
      return await runMutationTool<CloneIntegrationPlan>({
        action: "clone_integration",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { source_org_id: parsed.source_org_id, integration_id: parsed.integration_id, target_org_id: parsed.target_org_id },
        buildPlanData: () => ({
          source_org_id: parsed.source_org_id,
          integration_id: parsed.integration_id,
          target_org_id: parsed.target_org_id,
        }),
        describeDryRun: async (data) => {
          const sourceLabel = await formatOrgId(config, data.source_org_id);
          const targetLabel = await formatOrgId(config, data.target_org_id);
          const integrationLabel = await formatIntegrationId(config, data.source_org_id, data.integration_id);
          return `Dry run – clone integration ${integrationLabel} from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const result = await v1.cloneIntegration(
            config,
            sanitizePathSegment(data.source_org_id, "source_org_id"),
            sanitizePathSegment(data.integration_id, "integration_id"),
            sanitizePathSegment(data.target_org_id, "target_org_id")
          );
          const doneTargetLabel = await formatOrgId(config, data.target_org_id);
          const doneIntegrationLabel = await formatIntegrationId(config, data.source_org_id, data.integration_id);
          return `Integration ${doneIntegrationLabel} cloned to ${doneTargetLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}`;
        },
      });
    }

    if (name === "snyk_add_project_tags") {
      const parsed = AddProjectTagsArgsSchema.parse(args);
      type AddProjectTagsPlan = { org_id: string; project_ids: string[]; tags: { key: string; value?: string }[] };
      return await runMutationTool<AddProjectTagsPlan>({
        action: "add_project_tags",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags },
        buildPlanData: () => ({ org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags }),
        describeDryRun: (data) => {
          const totalOperations = data.project_ids.length * data.tags.length;
          return `Dry run – will add ${data.tags.length} tag(s) to ${data.project_ids.length} project(s) (${totalOperations} operations).\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const safeOrgId = sanitizePathSegment(data.org_id, "org_id");
          const results: { projectId: string; tag: { key: string; value?: string }; ok: boolean; error?: string }[] = [];
          for (const projectId of data.project_ids) {
            const safeProjectId = sanitizePathSegment(projectId, "project_id");
            for (const tag of data.tags) {
              try {
                await v1.addProjectTag(config, safeOrgId, safeProjectId, tag.key, tag.value);
                results.push({ projectId, tag, ok: true });
              } catch (err) {
                results.push({ projectId, tag, ok: false, error: String(err) });
              }
            }
          }
          return `Project tags added. Results:\n${JSON.stringify(results, null, 2)}`;
        },
      });
    }

    if (name === "snyk_remove_project_tags") {
      const parsed = RemoveProjectTagsArgsSchema.parse(args);
      type RemoveProjectTagsPlan = { org_id: string; project_ids: string[]; tag_keys: string[] };
      return await runMutationTool<RemoveProjectTagsPlan>({
        action: "remove_project_tags",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys },
        buildPlanData: () => ({ org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys }),
        describeDryRun: (data) => {
          const totalOperations = data.project_ids.length * data.tag_keys.length;
          return `Dry run – will remove ${data.tag_keys.length} tag key(s) from ${data.project_ids.length} project(s) (${totalOperations} operations).\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const safeOrgId = sanitizePathSegment(data.org_id, "org_id");
          const results: { projectId: string; key: string; ok: boolean; error?: string }[] = [];
          for (const projectId of data.project_ids) {
            const safeProjectId = sanitizePathSegment(projectId, "project_id");
            for (const key of data.tag_keys) {
              try {
                await v1.removeProjectTag(config, safeOrgId, safeProjectId, key);
                results.push({ projectId, key, ok: true });
              } catch (err) {
                results.push({ projectId, key, ok: false, error: String(err) });
              }
            }
          }
          return `Project tags removed. Results:\n${JSON.stringify(results, null, 2)}`;
        },
      });
    }

    if (name === "snyk_update_assets") {
      const parsed = UpdateAssetsArgsSchema.parse(args);
      const attributes: {
        class?: { display_name?: "A" | "B" | "C" | "D"; rank?: 1 | 2 | 3 | 4; locked?: boolean };
        labels?: { add?: string[]; remove?: string[] };
        tags?: { add?: Record<string, string>; remove?: string[] };
      } = {};
      if (parsed.class !== undefined) attributes.class = parsed.class;
      if (parsed.labels !== undefined) attributes.labels = parsed.labels;
      if (parsed.tags !== undefined) attributes.tags = parsed.tags;
      if (Object.keys(attributes).length === 0) {
        return {
          content: [{ type: "text", text: "Provide at least one of: class, labels, or tags to update." }],
          isError: true,
        };
      }
      type UpdateAssetsPlan = {
        group_id: string;
        asset_ids: string[];
        type: "repository" | "image" | "package";
        attributes: typeof attributes;
      };
      return await runMutationTool<UpdateAssetsPlan>({
        action: "update_assets",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { group_id: parsed.group_id, asset_ids: parsed.asset_ids, type: parsed.type, attributes },
        buildPlanData: () => ({ group_id: parsed.group_id, asset_ids: parsed.asset_ids, type: parsed.type, attributes }),
        describeDryRun: (data) => {
          const count = data.asset_ids.length;
          const scope = count === 1
            ? `asset ${data.asset_ids[0]}`
            : `${count} ${data.type} assets (one PATCH each)`;
          return `Dry run – will update ${scope} in group ${data.group_id}.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const results = await Promise.all(
            data.asset_ids.map(async (assetId) => {
              try {
                await rest.updateAsset(config, data.group_id, assetId, data.type, data.attributes);
                return { assetId, ok: true as const };
              } catch (err) {
                return { assetId, ok: false as const, error: err instanceof Error ? err.message : String(err) };
              }
            })
          );
          const succeeded = results.filter((r) => r.ok).length;
          const failed = results.length - succeeded;
          const summary = failed === 0
            ? `Updated all ${succeeded} asset(s).`
            : `Updated ${succeeded} of ${results.length} asset(s); ${failed} failed.`;
          return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
        },
      });
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await handleToolCall(request);
  return { content: result.content, isError: result.isError };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Snyk Admin MCP server running on stdio.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
