/**
 * Inventory Assets tools (REST, Early Access): list/filter, counts, field discovery, and bulk
 * update. Org or group scope.
 *
 * These sit beside the Asset API tools in assets.ts, which an earlier version of this server
 * dropped Inventory tools in favour of (see NOTES.md "Scope decisions"). What changed since,
 * verified live: the API now returns repositories (not only container images), its PATCH has
 * `{ add, remove }` forms for labels and tags, and the bulk PATCH is the only way to update
 * many assets in one request. What didn't change: the two APIs use different, non-
 * interchangeable asset IDs — so every description says which tools produce and accept which
 * IDs, and the ID schema below rejects an Asset API ID with a pointer to the right tool.
 */
import { z } from "zod";
import * as inv from "../snyk/inventory.js";
import type { SnykApiConfig } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, pageCursors } from "./format.js";

/** Shared lead-in for every description, so a caller can't miss which asset store this is. */
const INVENTORY_NOTE =
  "Inventory Assets API (Early Access) — a separate asset store from the Asset API tools (snyk_search_assets, snyk_get_asset, snyk_update_assets). " +
  "Its asset IDs are dashed UUIDs; theirs are 32-character hex; neither API accepts the other's IDs. " +
  "Labels and tags are separate too: values set here don't appear in the Asset API, or the other way round. " +
  "Covers repositories, container images, and SBOMs (not package assets), at org or group scope.";

const RSQL_HINT =
  "RSQL filter, e.g. `type==repositories;visibility==public` (`;` = AND, `,` = OR), `name==*goof*` (wildcards), `labels=in=(prod,staging)`, `tags.env==production`, `key.repositories==github.com/org/repo`. Use snyk_list_inventory_fields to see the fields.";

const ScopeFields = {
  org_id: z.string().optional().describe("Org ID — provide this or group_id, not both"),
  group_id: z.string().optional().describe("Group ID — provide this or org_id, not both"),
};

function resolveScope(args: { org_id?: string; group_id?: string }): inv.InventoryScope {
  if ((args.org_id ? 1 : 0) + (args.group_id ? 1 : 0) !== 1) throw new Error("Provide exactly one of org_id or group_id.");
  return args.org_id ? { kind: "orgs", id: args.org_id } : { kind: "groups", id: args.group_id! };
}

async function describeScope(config: SnykApiConfig, scope: inv.InventoryScope): Promise<string> {
  return scope.kind === "orgs" ? `org ${await formatOrgId(config, scope.id)}` : `group ${scope.id}`;
}

/** Asset API IDs look like this (live: e.g. 6246f60218d564511ed43248308ac3d5). */
const ASSET_API_ID_PATTERN = /^[0-9a-f]{32}$/i;

/**
 * An Inventory asset ID. An Asset API ID is rejected with a message naming the tool that does
 * take it — passing IDs across the two APIs was the failure that got the previous Inventory
 * tools removed, and the API itself would only answer with a bare 404.
 */
const InventoryAssetIdSchema = z.string().superRefine((id, ctx) => {
  if (ASSET_API_ID_PATTERN.test(id)) {
    ctx.addIssue({
      code: "custom",
      message: `${id} is an Asset API ID (32 hex characters, from snyk_search_assets), not an Inventory ID. Use snyk_update_assets for it, or get this asset's Inventory ID (a dashed UUID) from snyk_list_inventory_assets.`,
    });
  } else if (!z.guid().safeParse(id).success) {
    ctx.addIssue({ code: "custom", message: `${id} is not an Inventory asset ID (a dashed UUID from snyk_list_inventory_assets).` });
  }
});

const AssetTypeSchema = z.enum(inv.INVENTORY_ASSET_TYPES);
const PageLimitSchema = z.number().int().min(10).max(100).optional().describe("Results per page, 10-100 (API default 10)");
const PageCursorFields = {
  starting_after: z.string().optional().describe("Cursor: next_starting_after from a previous response"),
  ending_before: z.string().optional().describe("Cursor: prev_ending_before from a previous response"),
};

/** One line per asset: type, name, ID, then class/labels/tags when present. */
function describeAsset(asset: inv.InventoryAsset): string {
  const at = asset.attributes ?? {};
  const parts: string[] = [];
  if (at.class?.display_name) parts.push(`class ${at.class.display_name}`);
  if (at.labels?.length) parts.push(`labels: ${at.labels.join(", ")}`);
  const tags = Object.entries(at.tags ?? {});
  if (tags.length) parts.push(`tags: ${tags.map(([k, v]) => `${k}=${v}`).join(", ")}`);
  return `${asset.type} ${at.name ?? "(no name)"} (${asset.id})${parts.length ? ` — ${parts.join("; ")}` : ""}`;
}

function nextHint(next: string | null): string {
  return next ? `\n\nMore results: pass starting_after="${next}" (with the same filters) to get the next page.` : "";
}

/** Find a filter or group-by field by name (case-insensitive), or throw listing the valid names. */
async function resolveField(
  config: SnykApiConfig,
  scope: inv.InventoryScope,
  kind: "filters" | "groups",
  name: string,
  assetTypes?: inv.InventoryAssetType[]
): Promise<inv.InventoryField> {
  const fields = await inv.listAllInventoryFields(config, scope, kind, assetTypes);
  const match = fields.find((f) => f.attributes.name.toLowerCase() === name.toLowerCase());
  if (match) return match;
  const label = kind === "groups" ? "group-by" : "filter";
  throw new Error(`"${name}" is not a ${label} field here. Available: ${fields.map((f) => f.attributes.name).join(", ") || "(none)"}.`);
}

// --- List / filter assets ---

const ListInventoryAssetsArgsSchema = z.object({
  ...ScopeFields,
  filter: z.string().max(4000).optional().describe(RSQL_HINT),
  sort: z.string().optional().describe("Comma-separated sort fields; prefix with - for descending, e.g. -updated_at. Supported (live): created_at, updated_at, class, type, risk_score, issues, last_scan, built_at, and for SBOMs sbom_name, sbom_created_at, format, document_version. Not name."),
  fields: z.partialRecord(AssetTypeSchema, z.array(z.string()).min(1)).optional()
    .describe('Return only these attributes per asset type, e.g. { "repositories": ["name", "url", "labels"] }. id and type always come back.'),
  count_only: z.boolean().optional().describe("Return only the number of matching assets, no asset data"),
  limit: PageLimitSchema,
  ...PageCursorFields,
});

export const listInventoryAssets = defineTool({
  name: "snyk_list_inventory_assets",
  description: `List or filter assets in an org's or group's inventory, with the total count. ${INVENTORY_NOTE} Use this to get Inventory asset IDs for snyk_update_inventory_assets, to filter with RSQL (any combination of fields), or to list an org's assets. For package assets, or IDs for the other Asset tools, use snyk_search_assets instead. Read-only.`,
  schema: ListInventoryAssetsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const scope = resolveScope(parsed);
    const data = await inv.listInventoryAssets(config, scope, {
      filter: parsed.filter,
      sort: parsed.sort,
      fields: parsed.fields,
      meta_count: parsed.count_only ? "only" : "with",
      limit: parsed.limit,
      starting_after: parsed.starting_after,
      ending_before: parsed.ending_before,
    });
    const scopeLabel = await describeScope(config, scope);
    const total = data.meta?.count;
    const filterNote = parsed.filter ? ` matching ${parsed.filter}` : "";
    if (parsed.count_only) {
      return { content: [{ type: "text", text: `${total ?? "Unknown number of"} asset(s) in ${scopeLabel}${filterNote}.` }], isError: false };
    }
    const assets = data.data ?? [];
    const pagination = pageCursors(data.links);
    const header = `${assets.length} of ${total ?? "?"} asset(s) in ${scopeLabel}${filterNote}:`;
    const body = assets.length ? assets.map(describeAsset).join("\n") : "No assets.";
    const full = { data: assets, total: total ?? null, pagination };
    return {
      content: [{ type: "text", text: `${header}\n\n${body}${nextHint(pagination.next_starting_after)}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});

// --- Counts grouped by a field ---

const GetInventoryAssetCountsArgsSchema = z.object({
  ...ScopeFields,
  group_by: z.string().min(1).describe("Field to count by, e.g. visibility, class, org_id, scm_organization, registry, fork. snyk_list_inventory_fields lists them."),
  filter: z.string().max(4000).optional().describe(`Only count assets matching this. ${RSQL_HINT}`),
  asset_types: z.array(AssetTypeSchema).optional().describe("Only count these asset types"),
  sort: z.string().optional().describe("Default -count (largest group first). Also: value, created_at, updated_at; prefix - for descending."),
  limit: PageLimitSchema,
  ...PageCursorFields,
});

export const getInventoryAssetCounts = defineTool({
  name: "snyk_get_inventory_asset_counts",
  description: `Count assets in an org's or group's inventory, grouped by one field — e.g. public vs private repos, assets per class, or per org. Optionally filtered first. ${INVENTORY_NOTE} Read-only.`,
  schema: GetInventoryAssetCountsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const scope = resolveScope(parsed);
    // The API addresses group-by fields by ID; resolving the name here keeps callers from
    // needing a separate lookup call first.
    const field = await resolveField(config, scope, "groups", parsed.group_by, parsed.asset_types);
    // The total must cover the same assets as the groups, so asset_types joins the filter.
    // Parenthesised because in RSQL `;` (AND) binds tighter than `,` (OR).
    const totalFilter = [
      parsed.filter ? `(${parsed.filter})` : "",
      parsed.asset_types?.length ? `type=in=(${parsed.asset_types.join(",")})` : "",
    ].filter(Boolean).join(";");
    const [values, totals] = await Promise.all([
      inv.listInventoryGroupValues(config, scope, field.id, {
        filter: parsed.filter,
        sort: parsed.sort ?? "-count",
        asset_types: parsed.asset_types,
        limit: parsed.limit,
        starting_after: parsed.starting_after,
        ending_before: parsed.ending_before,
      }),
      inv.listInventoryAssets(config, scope, { filter: totalFilter || undefined, meta_count: "only" }),
    ]);
    const rows = values.data ?? [];
    // org_id values are bare IDs; show the org name next to each (names are cached briefly).
    const labels = await Promise.all(
      rows.map((r) => (field.attributes.name === "org_id" && r.attributes.value ? formatOrgId(config, r.attributes.value) : Promise.resolve(r.attributes.value)))
    );
    const lines = rows.map((r, i) => `${labels[i] === "" ? "(empty)" : labels[i]}: ${r.meta?.count ?? "?"}`);
    const pagination = pageCursors(values.links);
    const scopeLabel = await describeScope(config, scope);
    const total = totals.meta?.count;
    const name = field.attributes.name;
    const header = `${total ?? "?"} asset(s) in ${scopeLabel}${parsed.filter ? ` matching ${parsed.filter}` : ""}, by ${name}:`;
    // Some fields leave assets without a value out of every group, with no "(empty)" bucket —
    // live, org_id counts only the 2 container images in a 37-asset group, because repositories
    // have no org_id value. So when the groups come up short, say so rather than implying
    // they're the whole picture. Only checkable on a single, complete page.
    const sum = rows.reduce((n, r) => n + (r.meta?.count ?? 0), 0);
    const onePage = !pagination.next_starting_after && !parsed.starting_after && !parsed.ending_before;
    let coverage = "";
    if (onePage && total !== undefined && sum < total) {
      coverage = `\n\nNote: these groups add up to ${sum} of ${total} assets. The other ${total - sum} have no ${name} value, so they aren't in any group.`;
      if (name === "org_id") coverage += " For one org's total, use snyk_list_inventory_assets with that org_id and count_only.";
    }
    const full = { group_by: name, applies_to: field.attributes.asset_types ?? null, total: total ?? null, grouped: onePage ? sum : null, counts: rows.map((r) => ({ value: r.attributes.value, count: r.meta?.count ?? null })), pagination };
    return {
      content: [{ type: "text", text: `${header}\n\n${lines.join("\n") || "No groups."}${coverage}${nextHint(pagination.next_starting_after)}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});

// --- Field discovery and value suggestions ---

const ListInventoryFieldsArgsSchema = z.object({
  ...ScopeFields,
  asset_types: z.array(AssetTypeSchema).optional().describe("Only fields that apply to these asset types"),
  field: z.string().optional().describe("A filter field name: return suggested values for it instead of the field list"),
  q: z.string().max(100).optional().describe("With field: only values containing this text"),
  key: z.string().optional().describe("With an object field such as tags: only values for this key"),
  keys_only: z.boolean().optional().describe("With an object field such as tags: return its keys instead of values"),
  limit: PageLimitSchema,
  ...PageCursorFields,
});

export const listInventoryFields = defineTool({
  name: "snyk_list_inventory_fields",
  description: `List the fields you can filter Inventory assets by (for snyk_list_inventory_assets and snyk_get_inventory_asset_counts) and the fields counts can be grouped by. With field set, list suggested values for that filter field instead (e.g. field=visibility → public, private). ${INVENTORY_NOTE} Read-only.`,
  schema: ListInventoryFieldsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    const scope = resolveScope(parsed);
    if (parsed.field) {
      const field = await resolveField(config, scope, "filters", parsed.field, parsed.asset_types);
      const page = await inv.listInventoryFilterValues(config, scope, field.id, {
        q: parsed.q,
        key: parsed.key,
        keys_only: parsed.keys_only,
        limit: parsed.limit,
        starting_after: parsed.starting_after,
        ending_before: parsed.ending_before,
      });
      const values = (page.data ?? []).map((v) => v.attributes.value);
      const pagination = pageCursors(page.links);
      const body = values.length
        ? values.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n")
        : "No suggested values (the field may be empty for every asset).";
      return {
        content: [{ type: "text", text: `Values for ${field.attributes.name} (${field.attributes.type ?? "?"}):\n\n${body}${nextHint(pagination.next_starting_after)}` }],
        isError: false,
      };
    }
    const [filters, groups] = await Promise.all([
      inv.listAllInventoryFields(config, scope, "filters", parsed.asset_types),
      inv.listAllInventoryFields(config, scope, "groups", parsed.asset_types),
    ]);
    const filterLines = filters.map((f) => `${f.attributes.name} (${f.attributes.type ?? "?"}) — ${(f.attributes.asset_types ?? []).join(", ") || "all types"}`);
    const text =
      `Filter fields (${filters.length}), for the filter argument:\n${filterLines.join("\n")}\n\n` +
      `Group-by fields (${groups.length}), for snyk_get_inventory_asset_counts group_by:\n${groups.map((g) => `${g.attributes.name} — ${(g.attributes.asset_types ?? []).join(", ") || "all types"}`).join("\n")}\n\n` +
      `Filter syntax: ${RSQL_HINT}`;
    return { content: [{ type: "text", text }], isError: false };
  },
});

// --- Bulk update ---

const LabelSchema = z.string().regex(inv.INVENTORY_LABEL_PATTERN, "Labels must be 1-40 characters: letters, digits, and _/:?#@&=+%~-");
const TagKeySchema = z.string().regex(inv.INVENTORY_TAG_KEY_PATTERN, "Tag keys must be 1-30 characters: letters, digits, _ and -");
const TagValueSchema = z.string().regex(inv.INVENTORY_TAG_VALUE_PATTERN, "Tag values must be up to 40 characters: letters, digits, and _/:?#@&=+%~-");

const ClassSchema = z
  .object({
    display_name: z.enum(["A", "B", "C", "D"]).optional(),
    rank: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
    locked: z.boolean().optional(),
  })
  .refine((c) => c.display_name !== undefined || c.rank !== undefined, "class needs display_name (A-D) or rank (1-4)");

const UpdateInventoryAssetsArgsSchema = z.object({
  ...ScopeFields,
  asset_ids: z.array(InventoryAssetIdSchema).min(1).max(1000)
    .describe("Inventory asset IDs (dashed UUIDs from snyk_list_inventory_assets). Asset API IDs are rejected."),
  class: ClassSchema.optional().describe("Set the class on every listed asset, by display_name (A-D) or rank (1-4); locked stops Snyk reclassifying it"),
  labels: z.object({
    add: z.array(LabelSchema).max(50).optional(),
    remove: z.array(LabelSchema).max(50).optional(),
  }).optional().describe("Labels to add and/or remove on every listed asset. Other existing labels are kept."),
  tags: z.object({
    add: z.record(TagKeySchema, TagValueSchema).optional(),
    remove: z.array(TagKeySchema).max(100).optional(),
  }).optional().describe("Tags (key: value) to add, and tag keys to remove, on every listed asset. Other existing tags are kept; adding an existing key changes its value."),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

type ResolvedAsset = { id: string; type: inv.InventoryAssetType; name: string; class?: string };

/**
 * Look up each ID's type and name in the inventory. The bulk PATCH needs every asset's type,
 * and a request containing one unknown ID would fail as a whole, so unknown IDs are caught
 * here — at dry-run time — instead of on apply.
 */
async function resolveAssets(config: SnykApiConfig, scope: inv.InventoryScope, ids: string[]): Promise<{ found: ResolvedAsset[]; missing: string[]; badType: string[] }> {
  const byId = new Map<string, inv.InventoryAsset>();
  for (let i = 0; i < ids.length; i += inv.INVENTORY_UPDATE_MAX_PER_REQUEST) {
    const batch = ids.slice(i, i + inv.INVENTORY_UPDATE_MAX_PER_REQUEST);
    const page = await inv.listInventoryAssets(config, scope, { filter: `id=in=(${batch.join(",")})`, limit: 100 });
    for (const a of page.data ?? []) byId.set(a.id.toLowerCase(), a);
  }
  const found: ResolvedAsset[] = [];
  const missing: string[] = [];
  const badType: string[] = [];
  for (const id of ids) {
    const a = byId.get(id.toLowerCase());
    if (!a) missing.push(id);
    else if (!(inv.INVENTORY_ASSET_TYPES as readonly string[]).includes(a.type)) badType.push(`${id} (${a.type})`);
    else found.push({ id: a.id, type: a.type as inv.InventoryAssetType, name: a.attributes?.name ?? "(no name)", class: a.attributes?.class?.display_name });
  }
  return { found, missing, badType };
}

/** "+labels a, b; −tags owner" — what one update does, in one line. */
function describeChange(attrs: inv.InventoryAssetUpdate, currentClass?: string): string {
  const parts: string[] = [];
  if (attrs.class) {
    const target = attrs.class.display_name ?? `rank ${attrs.class.rank}`;
    parts.push(`class ${currentClass ?? "?"} → ${target}${attrs.class.locked !== undefined ? (attrs.class.locked ? " (locked)" : " (unlocked)") : ""}`);
  }
  if (attrs.labels?.add?.length) parts.push(`+labels ${attrs.labels.add.join(", ")}`);
  if (attrs.labels?.remove?.length) parts.push(`−labels ${attrs.labels.remove.join(", ")}`);
  const tagAdds = Object.entries(attrs.tags?.add ?? {});
  if (tagAdds.length) parts.push(`+tags ${tagAdds.map(([k, v]) => `${k}=${v}`).join(", ")}`);
  if (attrs.tags?.remove?.length) parts.push(`−tags ${attrs.tags.remove.join(", ")}`);
  return parts.join("; ");
}

/** Dry-run lines are capped so a 1,000-asset plan stays readable; the full list is in the plan JSON. */
const MAX_PLAN_LINES = 25;

export const updateInventoryAssets = defineTool({
  name: "snyk_update_inventory_assets",
  description: `Set class and/or add or remove labels and tags on many Inventory assets at once: one request per 100 assets, and each request is all-or-nothing (the API rolls back the whole batch on failure). Only adds and removes what you list — other labels and tags are kept. ${INVENTORY_NOTE} Takes Inventory asset IDs from snyk_list_inventory_assets; for Asset API IDs or package assets use snyk_update_assets instead. The dry run checks every ID exists first. Use dry_run=true first, then dry_run=false with approval_token to apply.`,
  schema: UpdateInventoryAssetsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const scope = resolveScope(parsed);
    const attributes: inv.InventoryAssetUpdate = {};
    if (parsed.class) attributes.class = parsed.class;
    const labelAdd = [...new Set(parsed.labels?.add ?? [])];
    const labelRemove = [...new Set(parsed.labels?.remove ?? [])];
    if (labelAdd.length || labelRemove.length) {
      attributes.labels = { ...(labelAdd.length ? { add: labelAdd } : {}), ...(labelRemove.length ? { remove: labelRemove } : {}) };
    }
    const tagAdd = parsed.tags?.add ?? {};
    const tagRemove = [...new Set(parsed.tags?.remove ?? [])];
    if (Object.keys(tagAdd).length || tagRemove.length) {
      attributes.tags = { ...(Object.keys(tagAdd).length ? { add: tagAdd } : {}), ...(tagRemove.length ? { remove: tagRemove } : {}) };
    }
    if (Object.keys(attributes).length === 0) {
      return { content: [{ type: "text", text: "Provide at least one of: class, labels (add/remove), or tags (add/remove)." }], isError: true };
    }
    const labelBoth = labelAdd.filter((l) => labelRemove.includes(l));
    const tagBoth = Object.keys(tagAdd).filter((k) => tagRemove.includes(k));
    if (labelBoth.length || tagBoth.length) {
      const what = [labelBoth.length ? `labels ${labelBoth.join(", ")}` : "", tagBoth.length ? `tag keys ${tagBoth.join(", ")}` : ""].filter(Boolean).join(" and ");
      return { content: [{ type: "text", text: `These are in both add and remove: ${what}. Pick one.` }], isError: true };
    }
    const assetIds = [...new Set(parsed.asset_ids.map((id) => id.toLowerCase()))];

    type UpdateInventoryPlan = { scope: inv.InventoryScope; assets: ResolvedAsset[]; attributes: inv.InventoryAssetUpdate };
    return await runMutationTool<UpdateInventoryPlan>({
      action: "update_inventory_assets",
      toolName: "snyk_update_inventory_assets",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { scope, asset_ids: assetIds, attributes },
      buildPlanData: async () => {
        const { found, missing, badType } = await resolveAssets(config, scope, assetIds);
        if (missing.length || badType.length) {
          const where = await describeScope(config, scope);
          const parts: string[] = [];
          if (missing.length) parts.push(`${missing.length} ID(s) not found in ${where}: ${missing.join(", ")}. Inventory IDs come from snyk_list_inventory_assets; an ID from another org or group won't match.`);
          if (badType.length) parts.push(`${badType.length} asset(s) of a type this tool can't update: ${badType.join(", ")}.`);
          throw new Error(`${parts.join(" ")} Nothing was planned.`);
        }
        return { scope, assets: found, attributes };
      },
      describeDryRun: async (data) => {
        const where = await describeScope(config, data.scope);
        const batches = Math.ceil(data.assets.length / inv.INVENTORY_UPDATE_MAX_PER_REQUEST);
        const lines = data.assets.slice(0, MAX_PLAN_LINES).map((a) => `- ${a.name} (${a.type}, ${a.id}): ${describeChange(data.attributes, a.class)}`);
        const more = data.assets.length > MAX_PLAN_LINES ? `\n- …and ${data.assets.length - MAX_PLAN_LINES} more (all listed in the plan below)` : "";
        return `Dry run – will update ${data.assets.length} Inventory asset(s) in ${where}, in ${batches} request(s) of up to ${inv.INVENTORY_UPDATE_MAX_PER_REQUEST}. Each request is all-or-nothing; separate requests are not. Only the labels and tags listed are added or removed — others are kept.\n\n${lines.join("\n")}${more}\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
      },
      apply: async (data) => {
        const steps: { step: string; ok: boolean; error?: string }[] = [];
        const total = data.assets.length;
        const batchCount = Math.ceil(total / inv.INVENTORY_UPDATE_MAX_PER_REQUEST);
        let updated = 0;
        for (let i = 0; i < total; i += inv.INVENTORY_UPDATE_MAX_PER_REQUEST) {
          const batch = data.assets.slice(i, i + inv.INVENTORY_UPDATE_MAX_PER_REQUEST);
          const label = `update ${batch.length} asset(s)${batchCount > 1 ? ` (request ${i / inv.INVENTORY_UPDATE_MAX_PER_REQUEST + 1}/${batchCount})` : ""}`;
          try {
            await inv.updateInventoryAssets(config, data.scope, batch.map((a) => ({ id: a.id, type: a.type, attributes: data.attributes })));
            steps.push({ step: label, ok: true });
            updated += batch.length;
          } catch (err) {
            steps.push({ step: label, ok: false, error: err instanceof Error ? err.message : String(err) });
          }
        }
        const failed = steps.filter((s) => !s.ok).length;
        const summary = failed === 0
          ? `Updated all ${updated} Inventory asset(s).`
          : `Updated ${updated} of ${total} Inventory asset(s); ${failed} of ${steps.length} request(s) failed and were rolled back by the API (no asset in a failed request was changed).`;
        return `${summary}\n\nSteps:\n${JSON.stringify(steps, null, 2)}`;
      },
    });
  },
});
