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
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import * as rest from "./snyk/rest.js";
import * as v1 from "./snyk/v1.js";
import { sanitizePathSegment, type SnykApiConfig } from "./snyk/types.js";
import { createApproval, consumeApproval } from "./approval.js";

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

// --- Bulk asset labels (project tags in V1) ---
const BulkLabelsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to apply labels to"),
  labels: z.array(z.object({
    key: z.string(),
    value: z.string().optional(),
  })).describe("Labels to add (key or key:value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Bulk update inventory assets (REST Inventory Assets API) ---
const BulkUpdateInventoryAssetsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  updates: z.array(z.object({
    asset_id: z.string().describe("Inventory asset ID to update"),
    class: z.string().optional().describe("Asset classification"),
    labels: z.array(z.string()).optional().describe("Free-form labels"),
    tags: z.record(z.string(), z.string()).optional().describe("Structured key:value tags"),
  })).min(1).describe("List of asset updates (each can set class, labels, and/or tags)"),
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

// --- Asset API (Early Access): search, get, relationships, update, aliases ---

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

const UpdateAssetArgsSchema = z.object({
  group_id: z.string().describe("Group ID that owns the asset"),
  asset_id: z.string().describe("Asset ID (UUID)"),
  type: z.enum(["repository", "image", "package"]).describe("Asset type"),
  class: z.object({
    display_name: z.enum(["A", "B", "C", "D"]).optional(),
    rank: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
    locked: z.boolean().optional(),
  }).optional().describe("Set asset class by display_name (A-D) or rank (1-4)."),
  labels: z.object({
    add: z.array(z.string()).optional(),
    remove: z.array(z.string()).optional(),
  }).optional().describe("Labels to add/remove."),
  tags: z.object({
    add: z.record(z.string(), z.string()).optional(),
    remove: z.array(z.string()).optional(),
  }).optional().describe("Tag key-value pairs to add, and tag keys to remove."),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

const ListRepositoryAliasesArgsSchema = z.object({
  group_id: z.string().optional().describe("Group ID (provide this or org_id)"),
  org_id: z.string().optional().describe("Org ID (provide this or group_id)"),
  url: z.string().optional().describe("Optional repository URL filter"),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional(),
  ending_before: z.string().optional(),
});

const AddRepositoryAliasArgsSchema = z.object({
  group_id: z.string().optional().describe("Group ID (provide this or org_id)"),
  org_id: z.string().optional().describe("Org ID (provide this or group_id)"),
  aliases: z.array(z.object({
    url: z.string().describe("The canonical repository URL"),
    new_url: z.string().describe("The alias URL to link to the canonical URL"),
  })).min(1).max(100).describe("Repository aliases to add"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

const RemoveRepositoryAliasArgsSchema = z.object({
  group_id: z.string().optional().describe("Group ID (provide this or org_id)"),
  org_id: z.string().optional().describe("Org ID (provide this or group_id)"),
  aliases: z.array(z.object({
    id: z.string().describe("The ID of the canonical asset-reference document that owns the alias"),
    url: z.string().describe("The canonical URL of the document that owns the alias"),
    new_url: z.string().describe("The aliased URL to detach from its canonical asset"),
  })).min(1).max(100).describe("Repository aliases to remove"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

/** Resolve org-or-group scope for repository alias endpoints. */
function resolveAssetScope(groupId?: string, orgId?: string): { scope: "groups" | "orgs"; id: string } {
  if (groupId && orgId) throw new Error("Provide either group_id or org_id, not both.");
  if (groupId) return { scope: "groups", id: groupId };
  if (orgId) return { scope: "orgs", id: orgId };
  throw new Error("Provide group_id or org_id.");
}

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
      name: "snyk_bulk_asset_labels",
      description: "Add labels (tags) to multiple projects in bulk. Uses Snyk V1 API (project tags). Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          project_ids: { type: "array", items: { type: "string" }, description: "List of project IDs to apply labels to" },
          labels: {
            type: "array",
            items: { type: "object", properties: { key: { type: "string" }, value: { type: "string" } }, required: ["key"] },
            description: "Labels to add (key or key:value)",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "project_ids", "labels"],
      },
    },
    {
      name: "snyk_bulk_update_inventory_assets",
      description: "Bulk update inventory assets (class, labels, tags) using the REST Inventory Assets API (PATCH /orgs/{org_id}/inventory/assets). Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          updates: {
            type: "array",
            items: {
              type: "object",
              properties: {
                asset_id: { type: "string", description: "Inventory asset ID to update" },
                class: { type: "string", description: "Asset classification" },
                labels: { type: "array", items: { type: "string" }, description: "Free-form labels" },
                tags: { type: "object", additionalProperties: { type: "string" }, description: "Structured key:value tags" },
              },
              required: ["asset_id"],
            },
            description: "List of asset updates",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "updates"],
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
      description: "List organizations accessible to the token (REST API). Read-only, no approval needed.",
      inputSchema: {
        type: "object",
        properties: {},
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
      name: "snyk_update_asset",
      description: "Update an asset's class, labels, and/or tags (REST Asset API, Early Access). PATCH /groups/{group_id}/assets/{asset_id}. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID that owns the asset" },
          asset_id: { type: "string", description: "Asset ID (UUID)" },
          type: { type: "string", enum: ["repository", "image", "package"], description: "Asset type" },
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
            description: "Labels to add/remove",
          },
          tags: {
            type: "object",
            properties: {
              add: { type: "object", additionalProperties: { type: "string" }, description: "Tag key-value pairs to add" },
              remove: { type: "array", items: { type: "string" }, description: "Tag keys to remove" },
            },
            description: "Tags to add/remove",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["group_id", "asset_id", "type"],
      },
    },
    {
      name: "snyk_list_repository_aliases",
      description: "List repository aliases for a group or org (REST Asset API, Early Access). GET /{groups|orgs}/{id}/assets/repository/aliases. Read-only. Provide group_id or org_id.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID (provide this or org_id)" },
          org_id: { type: "string", description: "Org ID (provide this or group_id)" },
          url: { type: "string", description: "Optional repository URL filter" },
          limit: { type: "number", description: "Records to return (10-100)" },
          starting_after: { type: "string" },
          ending_before: { type: "string" },
        },
      },
    },
    {
      name: "snyk_add_repository_alias",
      description: "Add repository aliases for a group or org (REST Asset API, Early Access). POST /{groups|orgs}/{id}/assets/repository/aliases. Provide group_id or org_id. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID (provide this or org_id)" },
          org_id: { type: "string", description: "Org ID (provide this or group_id)" },
          aliases: {
            type: "array",
            minItems: 1,
            maxItems: 100,
            items: {
              type: "object",
              properties: {
                url: { type: "string", description: "The canonical repository URL" },
                new_url: { type: "string", description: "The alias URL to link to the canonical URL" },
              },
              required: ["url", "new_url"],
            },
            description: "Repository aliases to add",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["aliases"],
      },
    },
    {
      name: "snyk_remove_repository_alias",
      description: "Remove repository aliases from a group or org (REST Asset API, Early Access). DELETE /{groups|orgs}/{id}/assets/repository/aliases. Provide group_id or org_id. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          group_id: { type: "string", description: "Group ID (provide this or org_id)" },
          org_id: { type: "string", description: "Org ID (provide this or group_id)" },
          aliases: {
            type: "array",
            minItems: 1,
            maxItems: 100,
            items: {
              type: "object",
              properties: {
                id: { type: "string", description: "The ID of the canonical asset-reference document that owns the alias" },
                url: { type: "string", description: "The canonical URL of the document that owns the alias" },
                new_url: { type: "string", description: "The aliased URL to detach from its canonical asset" },
              },
              required: ["id", "url", "new_url"],
            },
            description: "Repository aliases to remove",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["aliases"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const config = getConfig();
    if (name === "snyk_list_orgs") {
      const data = await rest.listOrgs(config);
      const lines = (data.data ?? []).map((org) => {
        const name = org.attributes?.name ?? "—";
        return `${name} (${org.id})`;
      });
      const summary = lines.length ? lines.join("\n") : "No organizations.";
      const full = { data: data.data?.map((org) => ({ id: org.id, name: org.attributes?.name ?? null, group_id: org.attributes?.group_id ?? null })) };
      return {
        content: [{ type: "text", text: `${summary}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
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

    if (name === "snyk_list_repository_aliases") {
      const parsed = ListRepositoryAliasesArgsSchema.parse(args);
      const { scope, id } = resolveAssetScope(parsed.group_id, parsed.org_id);
      const data = await rest.listRepositoryAliases(config, scope, id, {
        url: parsed.url,
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
      if (parsed.dry_run) {
        const plan = {
          action: "create_organization",
          name: parsed.name,
          group_id: resolvedGroupId,
          source_org_id: parsed.source_org_id,
        };
        const approval_token = createApproval(plan);
        const sourceOrgLabel = parsed.source_org_id ? ` (copying settings from ${await formatOrgId(config, parsed.source_org_id)})` : "";
        return {
          content: [{
            type: "text",
            text: `Dry run – will create organization "${parsed.name}" in group ${resolvedGroupId}${sourceOrgLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_create_organization with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "create_organization") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { name: string; group_id?: string; source_org_id?: string };
      const result = await v1.createOrganization(config, {
        name: p.name,
        group_id: p.group_id ? sanitizePathSegment(p.group_id, "group_id") : undefined,
        source_org_id: p.source_org_id ? sanitizePathSegment(p.source_org_id, "source_org_id") : undefined,
      });
      const resultOrgName = (result as { name?: string }).name ?? (result as { id?: string }).id;
      return {
        content: [{ type: "text", text: `Organization created: ${resultOrgName}. Result: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_copy_org_settings") {
      const parsed = CopySettingsArgsSchema.parse(args);
      const sourceLabel = await formatOrgId(config, parsed.source_org_id);
      const targetLabel = await formatOrgId(config, parsed.target_org_id);
      if (parsed.dry_run) {
        const settings = await v1.getOrgSettings(config, sanitizePathSegment(parsed.source_org_id, "source_org_id"));
        const plan = {
          action: "copy_org_settings",
          source_org_id: parsed.source_org_id,
          target_org_id: parsed.target_org_id,
          settings_to_apply: settings,
          note: "Only requestAccess and similar editable fields will be applied (V1 org settings).",
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – copy settings from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_copy_org_settings again with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "copy_org_settings") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { settings_to_apply?: Record<string, unknown>; target_org_id?: string };
      await v1.updateOrgSettings(config, sanitizePathSegment(p.target_org_id!, "target_org_id"), p.settings_to_apply ?? {});
      return {
        content: [{ type: "text", text: `Org settings copied to ${targetLabel}.` }],
        isError: false,
      };
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
      const sourceLabel = await formatOrgId(config, parsed.source_org_id);
      const targetLabel = await formatOrgId(config, parsed.target_org_id);
      const integrationLabel = await formatIntegrationId(config, parsed.source_org_id, parsed.integration_id);
      if (parsed.dry_run) {
        const plan = {
          action: "clone_integration",
          source_org_id: parsed.source_org_id,
          integration_id: parsed.integration_id,
          target_org_id: parsed.target_org_id,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – clone integration ${integrationLabel} from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_clone_integration with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "clone_integration") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { source_org_id: string; integration_id: string; target_org_id: string };
      const result = await v1.cloneIntegration(
        config,
        sanitizePathSegment(p.source_org_id, "source_org_id"),
        sanitizePathSegment(p.integration_id, "integration_id"),
        sanitizePathSegment(p.target_org_id, "target_org_id")
      );
      const doneTargetLabel = await formatOrgId(config, p.target_org_id);
      const doneIntegrationLabel = await formatIntegrationId(config, p.source_org_id, p.integration_id);
      return {
        content: [{ type: "text", text: `Integration ${doneIntegrationLabel} cloned to ${doneTargetLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_bulk_asset_labels") {
      const parsed = BulkLabelsArgsSchema.parse(args);
      if (parsed.dry_run) {
        const plan = {
          action: "bulk_asset_labels",
          org_id: parsed.org_id,
          project_ids: parsed.project_ids,
          labels: parsed.labels,
          total_operations: parsed.project_ids.length * parsed.labels.length,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will add ${parsed.labels.length} label(s) to ${parsed.project_ids.length} project(s) (${plan.total_operations} operations).\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_bulk_asset_labels with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "bulk_asset_labels") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { org_id: string; project_ids: string[]; labels: { key: string; value?: string }[] };
      const safeOrgId = sanitizePathSegment(p.org_id, "org_id");
      const results: { projectId: string; label: { key: string; value?: string }; ok: boolean; error?: string }[] = [];
      for (const projectId of p.project_ids) {
        const safeProjectId = sanitizePathSegment(projectId, "project_id");
        for (const label of p.labels) {
          try {
            await v1.addProjectTag(config, safeOrgId, safeProjectId, label.key, label.value);
            results.push({ projectId, label, ok: true });
          } catch (err) {
            results.push({ projectId, label, ok: false, error: String(err) });
          }
        }
      }
      return {
        content: [{ type: "text", text: `Bulk labels applied. Results:\n${JSON.stringify(results, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_bulk_update_inventory_assets") {
      const parsed = BulkUpdateInventoryAssetsArgsSchema.parse(args);
      const orgLabel = await formatOrgId(config, parsed.org_id);
      const data = parsed.updates.map((u) => {
        const attributes: { class?: string; labels?: string[]; tags?: Record<string, string> } = {};
        if (u.class !== undefined) attributes.class = u.class;
        if (u.labels !== undefined) attributes.labels = u.labels;
        if (u.tags !== undefined) attributes.tags = u.tags;
        return {
          type: "asset" as const,
          id: sanitizePathSegment(u.asset_id, "asset_id"),
          attributes,
        };
      });
      const withAttributes = data.filter((d) => Object.keys(d.attributes).length > 0);
      if (withAttributes.length === 0 && data.length > 0) {
        return {
          content: [{ type: "text", text: "Each update must specify at least one of: class, labels, or tags." }],
          isError: true,
        };
      }
      const body = { data: withAttributes.length > 0 ? withAttributes : data };
      if (parsed.dry_run) {
        const plan = {
          action: "bulk_update_inventory_assets",
          org_id: parsed.org_id,
          update_count: body.data.length,
          updates: parsed.updates,
          request_body: body,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will bulk update ${parsed.updates.length} inventory asset(s) in ${orgLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_bulk_update_inventory_assets with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "bulk_update_inventory_assets") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { org_id: string; request_body: typeof body };
      const result = await rest.bulkUpdateInventoryAssets(
        config,
        sanitizePathSegment(p.org_id, "org_id"),
        p.request_body
      );
      const doneLabel = await formatOrgId(config, p.org_id);
      return {
        content: [{ type: "text", text: `Bulk inventory assets updated in ${doneLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_update_asset") {
      const parsed = UpdateAssetArgsSchema.parse(args);
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
      if (parsed.dry_run) {
        const plan = {
          action: "update_asset",
          group_id: parsed.group_id,
          asset_id: parsed.asset_id,
          type: parsed.type,
          attributes,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will update asset ${parsed.asset_id} in group ${parsed.group_id}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_update_asset with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "update_asset") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { group_id: string; asset_id: string; type: "repository" | "image" | "package"; attributes: typeof attributes };
      const result = await rest.updateAsset(config, p.group_id, p.asset_id, p.type, p.attributes);
      return {
        content: [{ type: "text", text: `Asset ${p.asset_id} updated.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_add_repository_alias") {
      const parsed = AddRepositoryAliasArgsSchema.parse(args);
      const { scope, id } = resolveAssetScope(parsed.group_id, parsed.org_id);
      if (parsed.dry_run) {
        const plan = {
          action: "add_repository_alias",
          scope,
          scope_id: id,
          aliases: parsed.aliases,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will add ${parsed.aliases.length} repository alias(es) to ${scope} ${id}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_add_repository_alias with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "add_repository_alias") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { scope: "groups" | "orgs"; scope_id: string; aliases: { url: string; new_url: string }[] };
      const result = await rest.addRepositoryAliases(config, p.scope, p.scope_id, p.aliases);
      return {
        content: [{ type: "text", text: `Added ${p.aliases.length} repository alias(es) to ${p.scope} ${p.scope_id}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_remove_repository_alias") {
      const parsed = RemoveRepositoryAliasArgsSchema.parse(args);
      const { scope, id } = resolveAssetScope(parsed.group_id, parsed.org_id);
      if (parsed.dry_run) {
        const plan = {
          action: "remove_repository_alias",
          scope,
          scope_id: id,
          aliases: parsed.aliases,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will remove ${parsed.aliases.length} repository alias(es) from ${scope} ${id}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_remove_repository_alias with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "remove_repository_alias") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { scope: "groups" | "orgs"; scope_id: string; aliases: { id: string; url: string; new_url: string }[] };
      const result = await rest.removeRepositoryAliases(config, p.scope, p.scope_id, p.aliases);
      return {
        content: [{ type: "text", text: `Removed ${p.aliases.length} repository alias(es) from ${p.scope} ${p.scope_id}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
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
