#!/usr/bin/env node
/**
 * Snyk Admin MCP server entry point. Structure, top to bottom:
 *   1. Config/bootstrap (env vars, .env loading, the `server` object)
 *   2. Zod argument schemas — one per tool, used both to validate incoming calls
 *      (via `.parse()`) and, via `toInputSchema`/zod-to-json-schema, to generate the
 *      `inputSchema` objects the tool catalog below returns
 *   3. `ListToolsRequestSchema` handler — the static tool catalog returned to MCP clients
 *   4. `handleToolCall` — one big if/else dispatching each tool name to its Snyk API calls;
 *      every mutating tool routes through `runMutationTool` (mutation.ts) for the shared
 *      dry-run/approve/apply flow
 *   5. `CallToolRequestSchema` handler + `main()` — wires handleToolCall into the MCP SDK
 *      and starts the stdio transport
 */
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
import { zodToJsonSchema } from "zod-to-json-schema";
import * as rest from "./snyk/rest.js";
import * as v1 from "./snyk/v1.js";
import { sanitizePathSegment, type SnykApiConfig, type SnykRegion } from "./snyk/types.js";
import { runMutationTool, type ToolResult } from "./mutation.js";

const SNYK_TOKEN = process.env.SNYK_API_TOKEN ?? process.env.SNYK_TOKEN ?? "";
const SNYK_REGION = (process.env.SNYK_API_REGION ?? "us-01") as SnykRegion;

/** Build the API config from env vars, read once per tool call. Throws if no token is configured. */
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

/**
 * Convert a Zod args schema into the JSON Schema `tools/list` expects, so `inputSchema` is
 * always derived from the same Zod schema `.parse()` validates against instead of hand-kept
 * in sync with it. `removeAdditionalStrategy: "strict"` keeps `additionalProperties` permissive
 * (matching Zod's default "strip" parsing behavior) instead of the library's default of
 * emitting `additionalProperties: false`. `$schema` is stripped since it's meaningless nested
 * inside a tool's `inputSchema`.
 */
function toInputSchema(schema: z.ZodType<unknown>): Record<string, unknown> {
  const { $schema, ...jsonSchema } = zodToJsonSchema(schema, { $refStrategy: "root", removeAdditionalStrategy: "strict" }) as Record<string, unknown>;
  return jsonSchema;
}

// --- List orgs (REST) ---
const ListOrgsArgsSchema = z.object({
  limit: z.number().optional().describe("Number of results per page (API default: 10)"),
  starting_after: z.string().optional().describe("Return results after this cursor (from links.next of a previous response)"),
  ending_before: z.string().optional().describe("Return results before this cursor (from links.prev of a previous response)"),
  group_id: z.string().optional().describe("Filter: only return orgs within this group"),
  is_personal: z.boolean().optional().describe("Filter: if true, only return orgs not part of any group"),
  slug: z.string().optional().describe("Filter: only return orgs whose slug exactly matches this value"),
  name: z.string().optional().describe("Filter: only return orgs whose name contains this value"),
});

// --- List integrations (V1) ---
const ListIntegrationsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
});

// --- List projects (REST) ---
const ListProjectsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
});

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

// --- Move projects between orgs (V1). No REST equivalent, no batch endpoint — one HTTP call per project. ---
const MoveProjectsArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID the projects currently belong to"),
  target_org_id: z.string().describe("Organization ID to move the projects into"),
  project_ids: z.array(z.string()).min(1).describe("Project IDs to move"),
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

// --- Search audit logs (REST, GA). Read-only; exactly one of org_id/group_id. ---
const SearchAuditLogsArgsSchema = z.object({
  org_id: z.string().optional().describe("Organization ID to search (provide this or group_id, not both)"),
  group_id: z.string().optional().describe("Group ID to search (provide this or org_id, not both)"),
  from: z.string().optional().describe("Start of the search window, RFC3339 (e.g. 2024-01-02T16:30:00Z). Defaults to the start of yesterday if omitted."),
  to: z.string().optional().describe("End of the search window (exclusive), RFC3339."),
  events: z.array(z.string()).optional().describe("Only include these event types (e.g. org.settings.edit). Cannot be combined with exclude_events. Note: api.access events are omitted unless explicitly included here."),
  exclude_events: z.array(z.string()).optional().describe("Exclude these event types. Cannot be combined with events."),
  user_id: z.string().optional().describe("Filter to a specific user ID"),
  project_id: z.string().optional().describe("Filter to a specific project ID"),
  size: z.number().int().min(1).max(100).optional().describe("Results per page (1-100, default 100)"),
  sort_order: z.enum(["ASC", "DESC"]).optional().describe("Sort order, default DESC (newest first)"),
  cursor: z.string().optional().describe("Pagination cursor from a previous response's links.next"),
});

// --- Asset API (Early Access): search, get, relationships, update ---

// Reuses rest.ts's AssetSearchAttributes instead of redeclaring the same recursive shape
// here — two independent type definitions for one filter shape could drift silently if
// either changed without the other (flagged in review; see NOTES.md).
const AssetSearchAttributesSchema: z.ZodType<rest.AssetSearchAttributes> = z.lazy(() =>
  z.object({
    attribute: z.string().optional().describe("Asset attribute to filter on (e.g. name, type, class, labels, tags.<key>). Omit when using a logical operator (and/or)."),
    operator: z.string().describe("Operator: and, or, equal, not_equal, contains, not_contains, starts_with, ends_with, in, not_in, greater_than, lower_than, equal_or_greater_than, equal_or_lower_than."),
    values: z.array(z.union([z.string(), z.number(), z.boolean(), AssetSearchAttributesSchema])).describe("Values, or nested filter objects when using and/or."),
  })
);

const SearchAssetsArgsSchema = z.object({
  group_id: z.string().describe("Group ID to search assets in"),
  query: z.object({ attributes: AssetSearchAttributesSchema }).optional().describe("Optional filter. Omit to list all assets."),
  limit: z.number().int().min(10).max(100).optional().describe("Records to return (10-100)"),
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
  // No default: a caller omitting this while targeting an image/package asset used to
  // silently send "repository" instead of failing fast with a clear validation error.
  type: z.enum(["repository", "image", "package"]).describe("Asset type — all asset_ids must be of this type"),
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

/**
 * The tool catalog every MCP client sees via `tools/list`. Each `inputSchema` is generated
 * from the same Zod schema `.parse()` validates against (via `toInputSchema` above), so the
 * two can no longer drift apart the way hand-written duplicates did.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "snyk_copy_org_settings",
      description: "Copy organization settings from a source org to a target org: V1 org settings (e.g. requestAccess) via Snyk's V1 API, plus SAST settings (Snyk Code enablement/autofix), Open Source language settings, and Secrets settings (all via the REST API; Secrets settings is Early Access/beta). Always run with dry_run=true first to get a plan and approval_token, then run with dry_run=false and approval_token to apply.",
      inputSchema: toInputSchema(CopySettingsArgsSchema),
    },
    {
      name: "snyk_clone_integration",
      description: "Clone an integration (with settings and credentials) from one organization to another. Uses Snyk V1 API. CLI integrations are not supported (rejected). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: toInputSchema(CloneIntegrationArgsSchema),
    },
    {
      name: "snyk_add_project_tags",
      description: "Add tags to multiple projects (one V1 API call per project x tag, not a single batch request). Uses Snyk V1 API (project tags). Note: these are project tags, not asset labels — use snyk_update_assets for asset labels. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: toInputSchema(AddProjectTagsArgsSchema),
    },
    {
      name: "snyk_remove_project_tags",
      description: "Remove tags (by key) from multiple projects (one V1 API call per project x key, not a single batch request). Uses Snyk V1 API (project tags). Removal is by key only — no value needed. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: toInputSchema(RemoveProjectTagsArgsSchema),
    },
    {
      name: "snyk_move_projects",
      description: "Move one or more projects from a source org to a target org. Uses Snyk V1 API (no REST equivalent exists). One API call per project — no batch endpoint. Requires group-admin permissions; moving across group boundaries needs a personal API key rather than a service account key. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: toInputSchema(MoveProjectsArgsSchema),
    },
    {
      name: "snyk_create_organization",
      description: "Create a new Snyk organization. Uses Snyk V1 API (POST /org). Optional: group_id (required for group/Enterprise), source_org_id (copy settings from template). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: toInputSchema(CreateOrganizationArgsSchema),
    },
    {
      name: "snyk_list_orgs",
      description: "List organizations accessible to the token (REST API). Read-only. Supports cursor pagination and filters. Returns a `links.next` cursor for the next page.",
      inputSchema: toInputSchema(ListOrgsArgsSchema),
    },
    {
      name: "snyk_list_integrations",
      description: "List integrations for an organization (V1 API). Read-only.",
      inputSchema: toInputSchema(ListIntegrationsArgsSchema),
    },
    {
      name: "snyk_list_projects",
      description: "List projects for an organization (REST API). Read-only.",
      inputSchema: toInputSchema(ListProjectsArgsSchema),
    },
    {
      name: "snyk_search_audit_logs",
      description: "Search audit logs for an org or group (REST API, GA/stable). Read-only. Provide exactly one of org_id or group_id. Filter by time range (from/to, RFC3339), user_id, project_id, and event type (events or exclude_events, not both). Note: api.access events are omitted unless explicitly included via events. Supports cursor pagination.",
      inputSchema: toInputSchema(SearchAuditLogsArgsSchema),
    },
    {
      name: "snyk_search_assets",
      description: "Search assets in a group using the Asset API (REST, Early Access). POST /groups/{group_id}/assets/search. Read-only. Provide an optional filter query, or omit it to list all assets. Supports cursor pagination via limit/starting_after/ending_before.",
      inputSchema: toInputSchema(SearchAssetsArgsSchema),
    },
    {
      name: "snyk_get_asset",
      description: "Get a single asset by its ID within a group (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}. Read-only.",
      inputSchema: toInputSchema(GetAssetArgsSchema),
    },
    {
      name: "snyk_list_asset_projects",
      description: "List projects related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/projects. Read-only. Cursor pagination via starting_after/ending_before.",
      inputSchema: toInputSchema(ListAssetProjectsArgsSchema),
    },
    {
      name: "snyk_list_related_assets",
      description: "List assets related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/assets. Read-only. Optional type filter and cursor pagination.",
      inputSchema: toInputSchema(ListRelatedAssetsArgsSchema),
    },
    {
      name: "snyk_update_assets",
      description: "Update class, labels, and/or tags on one or more assets (REST Asset API, Early Access). Issues one PATCH per asset — the Asset API has no batch endpoint — and reports per-asset success/failure, so a partial failure leaves earlier assets updated. Works for repository, image, and package assets; pass a single ID in asset_ids to update just one. Get asset_ids from snyk_search_assets. Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: toInputSchema(UpdateAssetsArgsSchema),
    },
  ],
}));

/**
 * Dispatch one `tools/call` request to the matching Snyk API call(s). Every branch below
 * either handles a read-only tool directly, or (for mutations) delegates to
 * `runMutationTool` so the dry-run/approve/apply flow and its approval-token binding stay
 * centralized in one place rather than reimplemented per tool. The outer try/catch is the
 * single error boundary for this whole function — any thrown error becomes a normal
 * `isError: true` tool result instead of an unhandled rejection.
 */
async function handleToolCall(request: CallToolRequest): Promise<ToolResult> {
  const { name, arguments: args } = request.params;
  try {
    const config = getConfig();
    if (name === "snyk_list_orgs") {
      const a = ListOrgsArgsSchema.parse(args ?? {});
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
      const { org_id } = ListIntegrationsArgsSchema.parse(args);
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
      const { org_id } = ListProjectsArgsSchema.parse(args);
      const data = await rest.listProjects(config, sanitizePathSegment(org_id, "org_id"));
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_search_audit_logs") {
      const parsed = SearchAuditLogsArgsSchema.parse(args);
      if ((parsed.org_id ? 1 : 0) + (parsed.group_id ? 1 : 0) !== 1) {
        throw new Error("Provide exactly one of org_id or group_id.");
      }
      if (parsed.events && parsed.exclude_events) {
        throw new Error("Provide events or exclude_events, not both.");
      }
      const scope = parsed.org_id ? "orgs" : "groups";
      const scopeId = (parsed.org_id ?? parsed.group_id)!;
      const data = await rest.searchAuditLogs(config, scope, scopeId, {
        from: parsed.from,
        to: parsed.to,
        events: parsed.events,
        exclude_events: parsed.exclude_events,
        user_id: parsed.user_id,
        project_id: parsed.project_id,
        size: parsed.size,
        sort_order: parsed.sort_order,
        cursor: parsed.cursor,
      });
      const items = data.data?.items ?? [];
      const summary = items.length
        ? items.map((i) => `${i.created} — ${i.event}${i.project_id ? ` (project ${i.project_id})` : ""}`).join("\n")
        : "No audit log entries in this window.";
      const nextHint = data.links?.next
        ? `\n\nNext page cursor: pass cursor="${data.links.next}" to get the next page.`
        : "";
      return {
        content: [{ type: "text", text: `${summary}${nextHint}\n\nFull data:\n${JSON.stringify(data, null, 2)}` }],
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
      type CreateOrgPlan = { name: string; group_id: string; source_org_id?: string };
      return await runMutationTool<CreateOrgPlan>({
        action: "create_organization",
        toolName: "snyk_create_organization",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        // Bind on the raw group_id (possibly undefined), not a resolved value — resolving
        // rebinds on every apply call too, so a shifting org list between dry run and apply
        // could spuriously invalidate an otherwise-unchanged approval. Resolution only needs
        // to happen once, at dry-run time, and its result is frozen into the stored plan;
        // apply reads data.group_id from that plan and never re-resolves.
        bindingArgs: { name: parsed.name, group_id: parsed.group_id, source_org_id: parsed.source_org_id },
        buildPlanData: async () => {
          const resolvedGroupId = parsed.group_id ?? (await rest.getDefaultGroupId(config));
          if (!resolvedGroupId) {
            throw new Error("No group_id provided and none could be inferred (token may have only personal orgs or no orgs). Provide group_id explicitly, or use snyk_list_orgs to get an org's group_id from attributes.");
          }
          return { name: parsed.name, group_id: resolvedGroupId, source_org_id: parsed.source_org_id };
        },
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
      type CopySettingsPlan = {
        source_org_id: string;
        target_org_id: string;
        settings_to_apply: Record<string, unknown>;
        sast_settings_to_apply: rest.SastSettingsResource;
        language_settings_to_apply: rest.LanguageSettingsMap;
        secrets_settings_to_apply: rest.SecretsSettingsResource;
      };
      return await runMutationTool<CopySettingsPlan>({
        action: "copy_org_settings",
        toolName: "snyk_copy_org_settings",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id },
        buildPlanData: async () => {
          const safeSourceOrgId = sanitizePathSegment(parsed.source_org_id, "source_org_id");
          const [settings_to_apply, sast_settings_to_apply, languageSettings, secrets_settings_to_apply] = await Promise.all([
            v1.getOrgSettings(config, safeSourceOrgId),
            rest.getSastSettings(config, safeSourceOrgId),
            rest.getLanguageSettings(config, safeSourceOrgId),
            rest.getSecretsSettings(config, safeSourceOrgId),
          ]);
          return {
            source_org_id: parsed.source_org_id,
            target_org_id: parsed.target_org_id,
            settings_to_apply,
            sast_settings_to_apply,
            language_settings_to_apply: languageSettings.attributes.languages ?? {},
            secrets_settings_to_apply,
          };
        },
        describeDryRun: async (data) => {
          const sourceLabel = await formatOrgId(config, data.source_org_id);
          const targetLabel = await formatOrgId(config, data.target_org_id);
          const configured = Object.entries(data.language_settings_to_apply)
            .filter(([, packageManagers]) => Object.keys(packageManagers).length > 0)
            .map(([language]) => language);
          const emptyCount = Object.keys(data.language_settings_to_apply).length - configured.length;
          const languageSummary = configured.length
            ? `${configured.length} language setting(s): ${configured.join(", ")}`
            : "no language settings";
          const emptyNote = emptyCount ? `; ${emptyCount} language(s) skipped, nothing configured at the source` : "";
          return `Dry run – copy settings from ${sourceLabel} to ${targetLabel} (V1 org settings + SAST settings + ${languageSummary}${emptyNote} + Secrets settings [secrets_enabled=${data.secrets_settings_to_apply.attributes.secrets_enabled}]).\n\nPlan:\n${JSON.stringify(data, null, 2)}\n\nNote: only requestAccess and similar editable fields are copied from V1 org settings; SAST, Open Source language, and Secrets settings are copied via the REST API (Secrets settings is Early Access/beta — version 2024-10-15~beta).`;
        },
        apply: async (data) => {
          const safeTargetOrgId = sanitizePathSegment(data.target_org_id, "target_org_id");
          // This writes to three separate endpoints and cannot be rolled back, so every step
          // is attempted and reported individually — a bare throw would leave the caller
          // unable to tell which settings actually landed on the target org.
          const steps: { step: string; ok: boolean; skipped?: boolean; note?: string; error?: string }[] = [];
          const record = async (step: string, run: () => Promise<unknown>) => {
            try {
              await run();
              steps.push({ step, ok: true });
            } catch (err) {
              steps.push({ step, ok: false, error: err instanceof Error ? err.message : String(err) });
            }
          };

          await record("org settings (V1)", () =>
            v1.updateOrgSettings(config, safeTargetOrgId, data.settings_to_apply)
          );
          await record("SAST settings", () =>
            rest.updateSastSettings(config, safeTargetOrgId, data.sast_settings_to_apply)
          );
          await record("Secrets settings", () =>
            rest.updateSecretsSettings(config, safeTargetOrgId, data.secrets_settings_to_apply)
          );
          await Promise.all(
            Object.entries(data.language_settings_to_apply).map(([language, packageManagers]) => {
              // `package_managers` is a oneOf across the six per-language schemas, and an empty
              // object matches all of them, so the API rejects `{}` with "must match exactly one
              // schema in oneOf". An empty object also means the source org has nothing
              // configured for that language, so there is genuinely nothing to copy.
              if (Object.keys(packageManagers).length === 0) {
                steps.push({
                  step: `language settings (${language})`,
                  ok: true,
                  skipped: true,
                  note: "source org has no package manager settings for this language",
                });
                return Promise.resolve();
              }
              return record(`language settings (${language})`, () =>
                rest.updateLanguageSettings(config, safeTargetOrgId, language, packageManagers)
              );
            })
          );

          const failed = steps.filter((s) => !s.ok);
          const skipped = steps.filter((s) => s.skipped);
          const applied = steps.length - failed.length - skipped.length;
          const targetLabel = await formatOrgId(config, data.target_org_id);
          const skippedNote = skipped.length ? ` (${skipped.length} skipped — nothing configured at the source)` : "";
          const summary = failed.length === 0
            ? `Copied ${applied} setting group(s) to ${targetLabel}${skippedNote}.`
            : `Copied ${applied} of ${steps.length - skipped.length} setting group(s) to ${targetLabel}${skippedNote}; ${failed.length} failed — the target org is partially configured.`;
          return `${summary}\n\nSteps:\n${JSON.stringify(steps, null, 2)}`;
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
        toolName: "snyk_clone_integration",
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
        toolName: "snyk_add_project_tags",
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
          const operations = data.project_ids.flatMap((projectId) => data.tags.map((tag) => ({ projectId, tag })));
          const results = await Promise.all(
            operations.map(async ({ projectId, tag }) => {
              try {
                await v1.addProjectTag(config, safeOrgId, sanitizePathSegment(projectId, "project_id"), tag.key, tag.value);
                return { projectId, tag, ok: true as const };
              } catch (err) {
                return { projectId, tag, ok: false as const, error: String(err) };
              }
            })
          );
          return `Project tags added. Results:\n${JSON.stringify(results, null, 2)}`;
        },
      });
    }

    if (name === "snyk_remove_project_tags") {
      const parsed = RemoveProjectTagsArgsSchema.parse(args);
      type RemoveProjectTagsPlan = { org_id: string; project_ids: string[]; tag_keys: string[] };
      return await runMutationTool<RemoveProjectTagsPlan>({
        action: "remove_project_tags",
        toolName: "snyk_remove_project_tags",
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
          const operations = data.project_ids.flatMap((projectId) => data.tag_keys.map((key) => ({ projectId, key })));
          const results = await Promise.all(
            operations.map(async ({ projectId, key }) => {
              try {
                await v1.removeProjectTag(config, safeOrgId, sanitizePathSegment(projectId, "project_id"), key);
                return { projectId, key, ok: true as const };
              } catch (err) {
                return { projectId, key, ok: false as const, error: String(err) };
              }
            })
          );
          return `Project tags removed. Results:\n${JSON.stringify(results, null, 2)}`;
        },
      });
    }

    if (name === "snyk_move_projects") {
      const parsed = MoveProjectsArgsSchema.parse(args);
      type MoveProjectsPlan = { source_org_id: string; target_org_id: string; project_ids: string[] };
      return await runMutationTool<MoveProjectsPlan>({
        action: "move_projects",
        toolName: "snyk_move_projects",
        dryRun: parsed.dry_run,
        approvalToken: parsed.approval_token,
        bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id, project_ids: parsed.project_ids },
        buildPlanData: () => ({ source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id, project_ids: parsed.project_ids }),
        describeDryRun: async (data) => {
          const sourceLabel = await formatOrgId(config, data.source_org_id);
          const targetLabel = await formatOrgId(config, data.target_org_id);
          return `Dry run – will move ${data.project_ids.length} project(s) from ${sourceLabel} to ${targetLabel} (one V1 API call per project; not atomic — a partial failure leaves some projects moved and some not). Requires group-admin permissions; moving across group boundaries needs a personal API key.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
        },
        apply: async (data) => {
          const safeSourceOrgId = sanitizePathSegment(data.source_org_id, "source_org_id");
          const results = await Promise.all(
            data.project_ids.map(async (projectId) => {
              try {
                const result = await v1.moveProject(config, safeSourceOrgId, projectId, data.target_org_id);
                return { projectId, ok: true as const, result };
              } catch (err) {
                return { projectId, ok: false as const, error: err instanceof Error ? err.message : String(err) };
              }
            })
          );
          const succeeded = results.filter((r) => r.ok).length;
          const failed = results.length - succeeded;
          const targetLabel = await formatOrgId(config, data.target_org_id);
          const summary = failed === 0
            ? `Moved all ${succeeded} project(s) to ${targetLabel}.`
            : `Moved ${succeeded} of ${results.length} project(s) to ${targetLabel}; ${failed} failed — those remain in the source org.`;
          return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
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
        toolName: "snyk_update_assets",
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

// The MCP SDK's expected return type for tools/call is a large union that a plain
// ToolResult value doesn't structurally satisfy when passed through directly (a TypeScript
// quirk with how it checks large unions against a non-literal object) — rebuilding a fresh
// literal here from `result`'s fields is what makes this typecheck.
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await handleToolCall(request);
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
