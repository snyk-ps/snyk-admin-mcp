/**
 * Client for the Inventory Assets API (REST, Early Access / beta), used by the
 * snyk_*_inventory_* tools. Same endpoints under three scopes — tenant, org, and group —
 * of which this client supports org and group.
 * Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/inventory-assets
 *
 * This is a different asset store from the Asset API in rest.ts (`/groups/{id}/assets`):
 * - IDs are dashed UUIDs here, 32-char hex there, and neither API accepts the other's IDs
 *   (both 404, verified live).
 * - It covers repositories, container images, and SBOMs, but not package assets.
 * - Updates have a real bulk endpoint (100 assets per request, all-or-nothing per request).
 *
 * Live-verified quirks the code relies on:
 * - `filter` is an RSQL string (`type==repositories;visibility==public`). The spec says the
 *   `type` filter only accepts `container_images`, but `type==repositories` works.
 * - `fields` and the aggregation `aggregate` param are deepObject (`fields[repositories]=a,b`);
 *   `meta_fields` and `asset_types` are comma-separated.
 * - The `/lookup` and `/id` endpoints in the spec 404 on the live API, and the
 *   `relationships/projects|targets` endpoints return empty lists even for repos with projects,
 *   so this client doesn't wrap them.
 */
import { cursorFromLink, restFetch, type PageLinks } from "./rest.js";
import { INVENTORY_API_VERSION, sanitizePathSegment, type SnykApiConfig } from "./types.js";

/** Which inventory to address: an org's or a group's. */
export type InventoryScope = { kind: "orgs" | "groups"; id: string };

/** JSON:API resource types of inventory assets. The bulk PATCH needs one per asset. */
export const INVENTORY_ASSET_TYPES = ["repositories", "container_images", "sboms"] as const;
export type InventoryAssetType = (typeof INVENTORY_ASSET_TYPES)[number];

/** The bulk PATCH accepts at most this many assets per request (`maxItems: 100`). */
export const INVENTORY_UPDATE_MAX_PER_REQUEST = 100;

/** Label rule from the PATCH schema: 1-40 chars of letters, digits, and `_/:?#@&=+%~-`. */
export const INVENTORY_LABEL_PATTERN = /^[a-zA-Z0-9_/:?#@&=+%~-]{1,40}$/;
/** Tag key rule from the PATCH schema: 1-30 chars of letters, digits, `_`, `-`. */
export const INVENTORY_TAG_KEY_PATTERN = /^[a-zA-Z0-9_-]{1,30}$/;
/** Tag value rule from the PATCH schema: up to 40 chars of letters, digits, and `_/:?#@&=+%~-`. */
export const INVENTORY_TAG_VALUE_PATTERN = /^[a-zA-Z0-9_/:?#@&=+%~-]{0,40}$/;

export type InventoryAsset = {
  type: string;
  id: string;
  attributes: {
    name?: string;
    class?: { display_name?: string; rank?: number; locked?: boolean };
    labels?: string[];
    tags?: Record<string, string>;
  } & Record<string, unknown>;
};
export type InventoryAssetPage = { data: InventoryAsset[]; links?: PageLinks; meta?: { count?: number } };

/** A filter field or a group-by field: what can go in `filter`, or what counts can be grouped by. */
export type InventoryField = { type: string; id: string; attributes: { name: string; type?: string; asset_types?: string[] } };
export type InventoryFieldPage = { data: InventoryField[]; links?: PageLinks };

export type InventoryFilterValue = { type: string; id: string; attributes: { value: unknown } };
export type InventoryFilterValuePage = { data: InventoryFilterValue[]; links?: PageLinks };

export type InventoryGroupValue = { type: string; id: string; attributes: { value: string }; meta?: { count?: number } & Record<string, unknown> };
export type InventoryGroupValuePage = { data: InventoryGroupValue[]; links?: PageLinks };

/**
 * Writable attributes. Only the `{ add, remove }` forms of labels and tags are modelled: the
 * API also accepts a bare array/object that replaces every existing value, which this client
 * deliberately can't send.
 */
export type InventoryAssetUpdate = {
  class?: { display_name?: "A" | "B" | "C" | "D"; rank?: 1 | 2 | 3 | 4; locked?: boolean };
  labels?: { add?: string[]; remove?: string[] };
  tags?: { add?: Record<string, string>; remove?: string[] };
};

type Page = { limit?: number; starting_after?: string; ending_before?: string };

function basePath(scope: InventoryScope): string {
  const id = sanitizePathSegment(scope.id, scope.kind === "orgs" ? "org_id" : "group_id");
  return `/${scope.kind}/${id}/inventory/assets`;
}

function appendPage(search: URLSearchParams, page: Page): void {
  if (page.limit !== undefined) search.append("limit", String(page.limit));
  if (page.starting_after) search.append("starting_after", page.starting_after);
  if (page.ending_before) search.append("ending_before", page.ending_before);
}

async function inventoryGet<T>(config: SnykApiConfig, path: string, search: URLSearchParams, label: string): Promise<T> {
  const qs = search.toString();
  const res = await restFetch(config, `${path}${qs ? `?${qs}` : ""}`, { version: INVENTORY_API_VERSION });
  if (!res.ok) throw new Error(`REST ${label} failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<T>;
}

/** List or filter assets. GET .../inventory/assets. `meta_count: "only"` returns just the total. */
export function listInventoryAssets(
  config: SnykApiConfig,
  scope: InventoryScope,
  opts: Page & {
    filter?: string;
    sort?: string;
    /** Sparse fieldsets per asset type, sent as `fields[<type>]=a,b`. */
    fields?: Partial<Record<InventoryAssetType, string[]>>;
    meta_count?: "with" | "only";
  } = {}
): Promise<InventoryAssetPage> {
  const search = new URLSearchParams();
  if (opts.filter) search.append("filter", opts.filter);
  if (opts.sort) search.append("sort", opts.sort);
  for (const [type, names] of Object.entries(opts.fields ?? {})) {
    if (names?.length) search.append(`fields[${type}]`, names.join(","));
  }
  if (opts.meta_count) search.append("meta_count", opts.meta_count);
  appendPage(search, opts);
  return inventoryGet(config, basePath(scope), search, "listInventoryAssets");
}

/** One page of filter fields (`kind: "filters"`) or group-by fields (`kind: "groups"`). */
export function listInventoryFields(
  config: SnykApiConfig,
  scope: InventoryScope,
  kind: "filters" | "groups",
  opts: Page & { asset_types?: InventoryAssetType[] } = {}
): Promise<InventoryFieldPage> {
  const search = new URLSearchParams();
  if (opts.asset_types?.length) search.append("asset_types", opts.asset_types.join(","));
  appendPage(search, opts);
  return inventoryGet(config, `${basePath(scope)}/${kind}`, search, `listInventoryFields(${kind})`);
}

/** Safety cap when paging through field lists (live: 36 filter fields, 7 group fields). */
const MAX_FIELD_PAGES = 10;

/** Every filter or group-by field, following cursors at 100 per page. */
export async function listAllInventoryFields(
  config: SnykApiConfig,
  scope: InventoryScope,
  kind: "filters" | "groups",
  asset_types?: InventoryAssetType[]
): Promise<InventoryField[]> {
  const out: InventoryField[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_FIELD_PAGES; i++) {
    const page = await listInventoryFields(config, scope, kind, { asset_types, limit: 100, starting_after: cursor });
    out.push(...(page.data ?? []));
    const next = cursorFromLink(page.links?.next, "starting_after");
    if (!next) return out;
    cursor = next;
  }
  return out;
}

/** Value suggestions for one filter field. GET .../inventory/assets/filters/{filter_id}/values. */
export function listInventoryFilterValues(
  config: SnykApiConfig,
  scope: InventoryScope,
  filterId: string,
  opts: Page & { q?: string; key?: string; keys_only?: boolean } = {}
): Promise<InventoryFilterValuePage> {
  const safeId = sanitizePathSegment(filterId, "filter_id");
  const search = new URLSearchParams();
  if (opts.q) search.append("q", opts.q);
  if (opts.key) search.append("key", opts.key);
  if (opts.keys_only !== undefined) search.append("keys_only", String(opts.keys_only));
  appendPage(search, opts);
  return inventoryGet(config, `${basePath(scope)}/filters/${safeId}/values`, search, "listInventoryFilterValues");
}

/** Asset counts per value of one group-by field. GET .../inventory/assets/groups/{group_field_id}/values. */
export function listInventoryGroupValues(
  config: SnykApiConfig,
  scope: InventoryScope,
  groupFieldId: string,
  opts: Page & { filter?: string; sort?: string; asset_types?: InventoryAssetType[] } = {}
): Promise<InventoryGroupValuePage> {
  const safeId = sanitizePathSegment(groupFieldId, "group_field_id");
  const search = new URLSearchParams();
  search.append("meta_fields", "count");
  if (opts.filter) search.append("filter", opts.filter);
  if (opts.sort) search.append("sort", opts.sort);
  if (opts.asset_types?.length) search.append("asset_types", opts.asset_types.join(","));
  appendPage(search, opts);
  return inventoryGet(config, `${basePath(scope)}/groups/${safeId}/values`, search, "listInventoryGroupValues");
}

/**
 * Update up to 100 assets in one request. PATCH .../inventory/assets, 204 on success.
 * Per the spec the request is transactional: every asset in it is updated, or none is.
 * Throws rather than truncating when given more than 100.
 */
export async function updateInventoryAssets(
  config: SnykApiConfig,
  scope: InventoryScope,
  items: { id: string; type: InventoryAssetType; attributes: InventoryAssetUpdate }[]
): Promise<void> {
  if (items.length === 0) return;
  if (items.length > INVENTORY_UPDATE_MAX_PER_REQUEST) {
    throw new Error(`At most ${INVENTORY_UPDATE_MAX_PER_REQUEST} assets per request (got ${items.length}); chunk the list.`);
  }
  const data = items.map((item) => ({
    id: sanitizePathSegment(item.id, "asset_id"),
    type: item.type,
    attributes: item.attributes,
  }));
  const res = await restFetch(config, basePath(scope), {
    method: "PATCH",
    body: JSON.stringify({ data }),
    version: INVENTORY_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST updateInventoryAssets failed: ${res.status} ${await res.text()}`);
}
