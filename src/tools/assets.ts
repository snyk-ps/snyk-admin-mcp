/** Asset API tools (REST, Early Access): search, get, relationships, and update. Group-scoped. */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import { runMutationTool } from "../mutation.js";
import { DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { issueCountsText, nextPageHint, pageCursors } from "./format.js";

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
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
});

const GetAssetArgsSchema = z.object({
  group_id: z.string().describe("Group ID that owns the asset"),
  asset_id: z.string().describe("Asset ID (UUID)"),
});

const ListAssetProjectsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
});

const ListRelatedAssetsArgsSchema = z.object({
  group_id: z.string(),
  asset_id: z.string(),
  type: z.enum(["repository", "package", "image"]).optional(),
  limit: z.number().int().min(10).max(100).optional(),
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
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

type RawAsset = {
  id: string;
  type: string;
  removed?: boolean;
  attributes?: Record<string, unknown>;
  relationships?: { organizations?: { data?: { id: string; attributes?: { name?: string } }[] } } & Record<string, unknown>;
};

/** Asset tags arrive as [{key, value}] or as an object; normalize to "key:value" strings. */
function tagStrings(tags: unknown): string[] {
  if (Array.isArray(tags)) return tags.map((t) => (t && typeof t === "object" ? `${(t as { key?: string }).key}:${(t as { value?: string }).value ?? ""}` : String(t)));
  if (tags && typeof tags === "object") return Object.entries(tags as Record<string, unknown>).map(([k, v]) => `${k}:${v}`);
  return [];
}

/**
 * The fields worth showing per asset in a list. A raw page is ~1-4KB per asset — most of it
 * per-developer activity and per-product coverage detail — so a 10-asset page was ~32K
 * characters (measured live). snyk_get_asset still returns one asset in full.
 */
function summarizeAsset(a: RawAsset) {
  const at = (a.attributes ?? {}) as Record<string, any>;
  const coverage = Array.isArray(at.coverage_control) ? (at.coverage_control as { name?: string; gap?: boolean }[]) : [];
  return {
    id: a.id,
    type: a.type,
    name: at.name ?? null,
    class: at.class?.display_name ?? null,
    labels: Array.isArray(at.labels) ? at.labels : [],
    tags: tagStrings(at.tags),
    url: at.browse_url ?? at.repository_url ?? null,
    ...(at.base_image ? { base_image: at.base_image } : {}),
    ...(at.file_path ? { file_path: at.file_path } : {}),
    ...(at.repository_freshness ? { freshness: at.repository_freshness } : {}),
    ...(at.archived ? { archived: true } : {}),
    ...(a.removed ? { removed: true } : {}),
    issues: at.issues_counts ?? null,
    scanned_by: coverage.filter((c) => !c.gap).map((c) => c.name),
    coverage_gaps: coverage.filter((c) => c.gap).map((c) => c.name),
    orgs: (a.relationships?.organizations?.data ?? []).map((o) => ({ id: o.id, name: o.attributes?.name ?? null })),
  };
}

function describeAsset(s: ReturnType<typeof summarizeAsset>): string {
  const parts: string[] = [];
  if (s.class) parts.push(`class ${s.class}`);
  if (s.labels.length) parts.push(`labels ${s.labels.join(", ")}`);
  if (s.tags.length) parts.push(`tags ${s.tags.join(", ")}`);
  const issues = issueCountsText(s.issues);
  if (issues) parts.push(`issues ${issues}`);
  if (s.coverage_gaps.length) parts.push(`coverage gaps: ${s.coverage_gaps.join(", ")}`);
  if (s.orgs.length) parts.push(`org ${s.orgs.map((o) => o.name ?? o.id).join(", ")}`);
  return `${s.type} ${s.name ?? "(no name)"} (${s.id})${parts.length ? ` — ${parts.join("; ")}` : ""}`;
}

/**
 * Render an Asset API page as one line per asset plus compact data, with `links` swapped for
 * bare cursors. Left raw, the only cursor a caller sees is the `links.next` path, and passing
 * that back as `starting_after` makes asset search answer 500 "pagination error" (verified live).
 */
function assetPageText(data: Record<string, unknown>, what: string): string {
  const assets = ((data.data as RawAsset[] | undefined) ?? []).map(summarizeAsset);
  const pagination = pageCursors(data.links as rest.PageLinks | undefined);
  const lines = assets.length ? assets.map(describeAsset).join("\n") : `No ${what}.`;
  return `${assets.length} ${what}${pagination.next_starting_after ? " (more on the next page)" : ""}:\n\n${lines}${nextPageHint(pagination.next_starting_after)}\n\nFull data (use snyk_get_asset for every attribute of one asset):\n${JSON.stringify({ data: assets, pagination }, null, 2)}`;
}

type RawAssetProject = { id: string; attributes?: Record<string, any> };

/** One line per project related to an asset: name, ID, type, org, branch, issues, last scan. */
function assetProjectsText(data: Record<string, unknown>): string {
  const projects = (data.data as RawAssetProject[] | undefined) ?? [];
  const pagination = pageCursors(data.links as rest.PageLinks | undefined);
  const lines = projects.map((p) => {
    const a = p.attributes ?? {};
    const where = [a.project_type, a.test_surface, a.target_reference ? `ref ${a.target_reference}` : "", a.organization_name ? `org ${a.organization_name}` : ""].filter(Boolean).join(", ");
    const issues = issueCountsText(a.issues_counts);
    return `${a.name ?? "(no name)"} (${p.id})${where ? ` — ${where}` : ""}${issues ? `; issues ${issues}` : ""}${a.last_scan ? `; last scan ${a.last_scan}` : ""}`;
  });
  const full = projects.map((p) => ({ id: p.id, name: p.attributes?.name ?? null, org_id: p.attributes?.organization_id ?? null, target_id: p.attributes?.target_id ?? null, url: p.attributes?.url ?? null }));
  return `${projects.length} project(s)${pagination.next_starting_after ? " (more on the next page)" : ""}:\n\n${lines.join("\n") || "No projects."}${nextPageHint(pagination.next_starting_after)}\n\nFull data:\n${JSON.stringify({ data: full, pagination }, null, 2)}`;
}

export const searchAssets = defineTool({
  name: "snyk_search_assets",
  description: "Search a group's assets (repositories, container images, packages) with the Asset API (Early Access), one line each with class, labels, tags, issue counts, coverage gaps, and orgs. Omit query to list all; page with limit/starting_after. Its asset IDs (32 hex characters) are what snyk_get_asset and snyk_update_assets take. The snyk_*_inventory_* tools are a separate asset store with different IDs, labels, and tags. Read-only.",
  schema: SearchAssetsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.searchAssets(config, parsed.group_id, parsed.query, {
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    return {
      content: [{ type: "text", text: assetPageText(data, "asset(s)") }],
      isError: false,
    };
  },
});

export const getAsset = defineTool({
  name: "snyk_get_asset",
  description: "Get every attribute of one Asset API asset (32-hex ID from snyk_search_assets) in a group: languages, developers, per-product coverage, and more. Read-only.",
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
  description: "List the Snyk projects behind an Asset API asset (32-hex ID), one line each with type, org, branch, issue counts, and last scan. Read-only.",
  schema: ListAssetProjectsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const data = await rest.listAssetProjects(config, parsed.group_id, parsed.asset_id, {
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    return {
      content: [{ type: "text", text: assetProjectsText(data) }],
      isError: false,
    };
  },
});

export const listRelatedAssets = defineTool({
  name: "snyk_list_related_assets",
  description: "List assets related to an Asset API asset (32-hex ID), e.g. the images built from a repository; optional type filter. Read-only.",
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
      content: [{ type: "text", text: assetPageText(data, "related asset(s)") }],
      isError: false,
    };
  },
});

export const updateAssets = defineTool({
  name: "snyk_update_assets",
  description: "Set class and/or add or remove labels and tags on Asset API assets (32-hex IDs from snyk_search_assets; repository, image, or package, one type per call). One PATCH per asset, so a partial failure leaves earlier assets updated. The dry run checks that each ID exists and has that type. Not for Inventory IDs (dashed UUIDs): use snyk_update_inventory_assets, which also updates up to 100 assets per all-or-nothing request. Use dry_run=true first, then dry_run=false with approval_token to apply.",
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
      /** "name (id)" per asset, for the dry-run text only. */
      names: string[];
    };
    return await runMutationTool<UpdateAssetsPlan>({
      action: "update_assets",
      toolName: "snyk_update_assets",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { group_id: parsed.group_id, asset_ids: parsed.asset_ids, type: parsed.type, attributes },
      // Look every asset up first: an unknown ID or the wrong `type` used to get an approval
      // token anyway and then fail, per asset, on apply.
      buildPlanData: async () => {
        const looked = await Promise.all(parsed.asset_ids.map(async (id) => ({ id, asset: await rest.findAsset(config, parsed.group_id, id) })));
        const missing = looked.filter((l) => !l.asset).map((l) => l.id);
        const wrongType = looked.filter((l) => l.asset && l.asset.type !== parsed.type).map((l) => `${l.id} (${l.asset!.type})`);
        if (missing.length || wrongType.length) {
          const parts: string[] = [];
          if (missing.length) parts.push(`${missing.length} asset ID(s) not found in group ${parsed.group_id}: ${missing.join(", ")}. Asset IDs come from snyk_search_assets (32 hex characters).`);
          if (wrongType.length) parts.push(`${wrongType.length} asset(s) are not of type ${parsed.type}: ${wrongType.join(", ")}. Call once per type.`);
          throw new Error(`${parts.join(" ")} Nothing was planned.`);
        }
        const names = looked.map((l) => `${l.asset!.name ?? "(no name)"} (${l.id})`);
        return { group_id: parsed.group_id, asset_ids: parsed.asset_ids, type: parsed.type, attributes, names };
      },
      describeDryRun: (data) => {
        const count = data.asset_ids.length;
        const scope = count === 1
          ? `${data.type} asset ${data.names[0]}`
          : `${count} ${data.type} assets (one PATCH each)`;
        const list = count > 1 ? `\n\n${data.names.slice(0, 25).map((n) => `- ${n}`).join("\n")}${count > 25 ? `\n- …and ${count - 25} more` : ""}` : "";
        const { names: _names, ...plan } = data;
        return `Dry run – will update ${scope} in group ${data.group_id}.${list}\n\nPlan:\n${JSON.stringify(plan, null, 2)}`;
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
