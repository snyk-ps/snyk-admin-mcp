/** Asset API tools (REST, Early Access): search, get, relationships, and update. Group-scoped. */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import { runMutationTool } from "../mutation.js";
import { DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { pageCursors } from "./format.js";

// --- Asset API (Early Access): search, get, relationships, update ---

// Reuses rest.ts's AssetSearchAttributes instead of redeclaring the same recursive shape
// here — two independent type definitions for one filter shape could drift silently if
// either changed without the other (flagged in review; see NOTES.md).
// The `id` names this recursive shape in the generated JSON Schema ("#/definitions/AssetFilter"),
// so the nested-filter reference reads meaningfully instead of as an auto-numbered "__schema0".
const AssetSearchAttributesSchema: z.ZodType<rest.AssetSearchAttributes> = z.lazy(() =>
  z.object({
    attribute: z.string().optional().describe("Asset attribute to filter on (e.g. name, type, class, labels, tags.<key>). Omit when using a logical operator (and/or)."),
    operator: z.string().describe("Operator: and, or, equal, not_equal, contains, not_contains, starts_with, ends_with, in, not_in, greater_than, lower_than, equal_or_greater_than, equal_or_lower_than."),
    values: z.array(z.union([z.string(), z.number(), z.boolean(), AssetSearchAttributesSchema])).describe("Values, or nested filter objects when using and/or."),
  })
).meta({ id: "AssetFilter" });

const SearchAssetsArgsSchema = z.object({
  group_id: z.string().describe("Group ID to search assets in"),
  query: z.object({ attributes: AssetSearchAttributesSchema }).optional().describe("Optional filter. Omit to list all assets."),
  limit: z.number().int().min(10).max(100).optional().describe("Records to return (10-100)"),
  starting_after: z.string().optional().describe("Cursor: next_starting_after from a previous response"),
  ending_before: z.string().optional().describe("Cursor: prev_ending_before from a previous response"),
});

const GetAssetArgsSchema = z.object({
  group_id: z.string().describe("Group ID that owns the asset"),
  asset_id: z.string().describe("Asset ID (UUID)"),
});

const ListAssetProjectsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional().describe("Cursor: next_starting_after from a previous response"),
  ending_before: z.string().optional().describe("Cursor: prev_ending_before from a previous response"),
});

const ListRelatedAssetsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  type: z.enum(["repository", "package", "image"]).optional(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional().describe("Cursor: next_starting_after from a previous response"),
  ending_before: z.string().optional().describe("Cursor: prev_ending_before from a previous response"),
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
    rank: z.literal([1, 2, 3, 4]).optional(),
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
 * Render a raw Asset API page with its `links` swapped for bare cursors. Left raw, the only
 * cursor a caller sees is the `links.next` path, and passing that back as `starting_after`
 * makes asset search answer 500 "pagination error" (verified live).
 */
function assetPageText(data: Record<string, unknown>): string {
  const { links, ...withoutLinks } = data as { links?: rest.PageLinks } & Record<string, unknown>;
  const pagination = pageCursors(links);
  const hint = pagination.next_starting_after
    ? `\n\nMore results: pass starting_after="${pagination.next_starting_after}" (with the same filters) to get the next page.`
    : "";
  return `${JSON.stringify({ ...withoutLinks, pagination }, null, 2)}${hint}`;
}

export const searchAssets = defineTool({
  name: "snyk_search_assets",
  description: "Search assets in a group using the Asset API (REST, Early Access). POST /groups/{group_id}/assets/search. Read-only. Provide an optional filter query, or omit it to list all assets. Supports cursor pagination via limit/starting_after/ending_before. Covers repository, image, and package assets; use this (not snyk_list_inventory_assets) to get IDs for snyk_get_asset and snyk_update_assets. Asset IDs here are 32-character hex (Asset API); the snyk_*_inventory_* tools use a separate Inventory API whose IDs are dashed UUIDs, and the two are not interchangeable. Labels and tags are separate between the two APIs as well.",
  schema: SearchAssetsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.searchAssets(config, parsed.group_id, parsed.query, {
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    return {
      content: [{ type: "text", text: assetPageText(data) }],
      isError: false,
    };
  },
});

export const getAsset = defineTool({
  name: "snyk_get_asset",
  description: "Get a single asset by its ID within a group (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}. Read-only.",
  schema: GetAssetArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.getAsset(config, parsed.group_id, parsed.asset_id);
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
      isError: false,
    };
  },
});

export const listAssetProjects = defineTool({
  name: "snyk_list_asset_projects",
  description: "List projects related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/projects. Read-only. Cursor pagination via starting_after/ending_before.",
  schema: ListAssetProjectsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.listAssetProjects(config, parsed.group_id, parsed.asset_id, {
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    return {
      content: [{ type: "text", text: assetPageText(data) }],
      isError: false,
    };
  },
});

export const listRelatedAssets = defineTool({
  name: "snyk_list_related_assets",
  description: "List assets related to an asset (REST Asset API, Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/assets. Read-only. Optional type filter and cursor pagination.",
  schema: ListRelatedAssetsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.listRelatedAssets(config, parsed.group_id, parsed.asset_id, {
      type: parsed.type,
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    return {
      content: [{ type: "text", text: assetPageText(data) }],
      isError: false,
    };
  },
});

export const updateAssets = defineTool({
  name: "snyk_update_assets",
  description: "Update class, labels, and/or tags on one or more assets (REST Asset API, Early Access). Issues one PATCH per asset — the Asset API has no batch endpoint — and reports per-asset success/failure, so a partial failure leaves earlier assets updated. Works for repository, image, and package assets; pass a single ID in asset_ids to update just one. Get asset_ids from snyk_search_assets. Asset IDs here are 32-character hex (Asset API); the snyk_*_inventory_* tools use a separate Inventory API whose IDs are dashed UUIDs, and the two are not interchangeable. Labels and tags are separate between the two APIs as well. For updating many repositories or images in single all-or-nothing requests, snyk_update_inventory_assets does that with Inventory IDs. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: UpdateAssetsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
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
  },
});
