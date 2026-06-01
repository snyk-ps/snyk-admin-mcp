import { ASSET_API_VERSION, assertAllowedUrl, getBaseUrl, REST_API_VERSION, sanitizeFieldSegment, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, restRateLimiter } from "./rateLimit.js";

/**
 * Snyk REST API (JSON:API). Use for: orgs, groups, projects, issues, etc.
 * Rate-limited to stay under 1620/min; retries on 429.
 * Docs: https://docs.snyk.io/snyk-api/rest-api/about-the-rest-api
 * Pass `version` to override the default API version for newer endpoints.
 */
export async function restFetch(
  config: SnykApiConfig,
  path: string,
  options: RequestInit & { version?: string } = {}
): Promise<Response> {
  const { version, ...fetchOptions } = options;
  const { rest } = getBaseUrl(config);
  const url = path.startsWith("http") ? path : `${rest}${path.startsWith("/") ? path : `/${path}`}`;
  const apiVersion = version ?? REST_API_VERSION;
  const versionParam = url.includes("?") ? `&version=${apiVersion}` : `?version=${apiVersion}`;
  const finalUrl = assertAllowedUrl(config, url + versionParam);
  return fetchWithRetry(restRateLimiter, () =>
    fetch(finalUrl, {
      ...fetchOptions,
      headers: {
        "Content-Type": "application/vnd.api+json",
        Authorization: `token ${config.token}`,
        ...fetchOptions.headers,
      },
    })
  );
}

export type ListOrgsResponse = {
  data: { id: string; attributes?: { name?: string; group_id?: string; slug?: string } }[];
  links?: { next?: string; prev?: string; first?: string; last?: string };
  meta?: { count?: number };
};

export async function listOrgs(
  config: SnykApiConfig,
  opts: {
    limit?: number;
    starting_after?: string;
    ending_before?: string;
    group_id?: string;
    is_personal?: boolean;
    slug?: string;
    name?: string;
  } = {}
): Promise<ListOrgsResponse> {
  const qs = buildQuery({
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    group_id: opts.group_id,
    is_personal: opts.is_personal === undefined ? undefined : String(opts.is_personal),
    slug: opts.slug,
    name: opts.name,
  });
  const res = await restFetch(config, `/orgs${qs}`);
  if (!res.ok) throw new Error(`REST listOrgs failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListOrgsResponse>;
}

/** Get the group_id from the first org the token can access (for accounts that require group_id to create orgs). */
export async function getDefaultGroupId(config: SnykApiConfig): Promise<string | null> {
  const { data } = await listOrgs(config);
  const firstWithGroup = data?.find((org) => org.attributes?.group_id);
  return firstWithGroup?.attributes?.group_id ?? null;
}

/** Get org display name by org ID (from listOrgs). Returns null if not found. */
export async function getOrgName(config: SnykApiConfig, orgId: string): Promise<string | null> {
  const { data } = await listOrgs(config);
  const org = data?.find((o) => o.id === orgId);
  return org?.attributes?.name ?? null;
}

export async function listProjects(
  config: SnykApiConfig,
  orgId: string
): Promise<{ data: { id: string; attributes?: { name?: string } }[] }> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/projects`);
  if (!res.ok) throw new Error(`REST listProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<{ data: { id: string; attributes?: { name?: string } }[] }>;
}

// ---------------------------------------------------------------------------
// Asset API (Early Access). Group-scoped asset search, lookup, update, and
// repository alias management. Uses ASSET_API_VERSION.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/asset
// ---------------------------------------------------------------------------

/** Scope for repository-alias endpoints: org-level or group-level. */
export type AssetScope = "orgs" | "groups";

/**
 * Allowlist of valid scope path segments. Looking the scope up here yields a
 * trusted constant literal, so caller-influenced values can never flow into the
 * request URL path (SSRF guard). Throws on anything outside the allowlist.
 */
const SCOPE_PATH_SEGMENT: Record<AssetScope, string> = { orgs: "orgs", groups: "groups" };
function safeScopeSegment(scope: AssetScope): string {
  const segment = SCOPE_PATH_SEGMENT[scope];
  if (!segment) throw new Error(`Invalid asset scope: ${String(scope)}`);
  return segment;
}

/** Recursive search filter node for the Asset search query. */
export interface AssetSearchAttributes {
  attribute?: string;
  operator: string;
  values: Array<string | number | boolean | AssetSearchAttributes>;
}

/** Build a query string from defined params (values are URL-encoded). */
function buildQuery(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.append(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/**
 * Search assets in a group (Early Access).
 * POST /groups/{group_id}/assets/search. Body may be empty or a query with attribute filters.
 */
export async function searchAssets(
  config: SnykApiConfig,
  groupId: string,
  query?: { attributes: AssetSearchAttributes },
  page: { limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const body = query ? { query } : {};
  const qs = buildQuery({ limit: page.limit, starting_after: page.starting_after, ending_before: page.ending_before });
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/search${qs}`, {
    method: "POST",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
    // This endpoint validates against a plain JSON schema and rejects the
    // JSON:API content type that restFetch sends by default.
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`REST searchAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get a single asset by its ID within a group (Early Access). GET /groups/{group_id}/assets/{asset_id}. */
export async function getAsset(
  config: SnykApiConfig,
  groupId: string,
  assetId: string
): Promise<Record<string, unknown>> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/${safeAssetId}`, {
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST getAsset failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** List projects related to an asset (Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/projects. */
export async function listAssetProjects(
  config: SnykApiConfig,
  groupId: string,
  assetId: string,
  page: { limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const qs = buildQuery({ limit: page.limit, starting_after: page.starting_after, ending_before: page.ending_before });
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/${safeAssetId}/relationships/projects${qs}`, {
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST listAssetProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** List assets related to an asset (Early Access). GET /groups/{group_id}/assets/{asset_id}/relationships/assets. */
export async function listRelatedAssets(
  config: SnykApiConfig,
  groupId: string,
  assetId: string,
  page: { type?: string; limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const qs = buildQuery({ type: page.type, limit: page.limit, starting_after: page.starting_after, ending_before: page.ending_before });
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/${safeAssetId}/relationships/assets${qs}`, {
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST listRelatedAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Update an asset's class, labels, and/or tags (Early Access).
 * PATCH /groups/{group_id}/assets/{asset_id}. Body is JSON:API: { data: { type, id, attributes } }.
 */
export async function updateAsset(
  config: SnykApiConfig,
  groupId: string,
  assetId: string,
  type: "repository" | "image" | "package",
  attributes: {
    class?: { display_name?: "A" | "B" | "C" | "D"; rank?: 1 | 2 | 3 | 4; locked?: boolean };
    labels?: { add?: string[]; remove?: string[] };
    tags?: { add?: Record<string, string>; remove?: string[] };
  }
): Promise<Record<string, unknown>> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const body = { data: { type, id: safeAssetId, attributes } };
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/${safeAssetId}`, {
    method: "PATCH",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST updateAsset failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** List repository aliases for a group or org (Early Access). GET /{scope}/{id}/assets/repository/aliases. */
export async function listRepositoryAliases(
  config: SnykApiConfig,
  scope: AssetScope,
  scopeId: string,
  page: { url?: string; limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const label = scope === "orgs" ? "org_id" : "group_id";
  const safeScope = safeScopeSegment(scope);
  const safeId = sanitizePathSegment(scopeId, label);
  const qs = buildQuery({ url: page.url, limit: page.limit, starting_after: page.starting_after, ending_before: page.ending_before });
  const res = await restFetch(config, `/${safeScope}/${safeId}/assets/repository/aliases${qs}`, {
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST listRepositoryAliases failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Add repository aliases for a group or org (Early Access).
 * POST /{scope}/{id}/assets/repository/aliases. Body: { data: [{ type: "asset_aliases", attributes: { url, new_url } }] }.
 */
export async function addRepositoryAliases(
  config: SnykApiConfig,
  scope: AssetScope,
  scopeId: string,
  aliases: Array<{ url: string; new_url: string }>
): Promise<Record<string, unknown>> {
  const label = scope === "orgs" ? "org_id" : "group_id";
  const safeScope = safeScopeSegment(scope);
  const safeId = sanitizePathSegment(scopeId, label);
  const body = {
    data: aliases.map((a) => ({ type: "asset_aliases" as const, attributes: { url: a.url, new_url: a.new_url } })),
  };
  const res = await restFetch(config, `/${safeScope}/${safeId}/assets/repository/aliases`, {
    method: "POST",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST addRepositoryAliases failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Remove repository aliases for a group or org (Early Access).
 * DELETE /{scope}/{id}/assets/repository/aliases. Body: { data: [{ type: "asset_aliases", id, attributes: { url, new_url } }] }.
 */
export async function removeRepositoryAliases(
  config: SnykApiConfig,
  scope: AssetScope,
  scopeId: string,
  aliases: Array<{ id: string; url: string; new_url: string }>
): Promise<Record<string, unknown>> {
  const label = scope === "orgs" ? "org_id" : "group_id";
  const safeScope = safeScopeSegment(scope);
  const safeId = sanitizePathSegment(scopeId, label);
  const body = {
    data: aliases.map((a) => ({
      type: "asset_aliases" as const,
      id: sanitizePathSegment(a.id, "alias_id"),
      attributes: { url: a.url, new_url: a.new_url },
    })),
  };
  const res = await restFetch(config, `/${safeScope}/${safeId}/assets/repository/aliases`, {
    method: "DELETE",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST removeRepositoryAliases failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Bulk update inventory assets (REST API). PATCH /orgs/{org_id}/inventory/assets. Body: JSON:API data array with type "asset", id, and attributes (class, labels, tags). */
export async function bulkUpdateInventoryAssets(
  config: SnykApiConfig,
  orgId: string,
  body: { data: Array<{ type: string; id: string; attributes: { class?: string; labels?: string[]; tags?: Record<string, string> } }> }
): Promise<Record<string, unknown>> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/inventory/assets`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`REST bulkUpdateInventoryAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Inventory Assets API (Early Access). Tenant/org/group-scoped asset listing,
// search (sync + async), single-asset get/update, relationships, and the
// filters/groups discovery endpoints. Uses ASSET_API_VERSION.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/inventory-assets
// ---------------------------------------------------------------------------

/** Scope for Inventory Assets endpoints: tenant, org, or group level. */
export type InventoryScope = "tenants" | "orgs" | "groups";

/**
 * Allowlist of valid inventory scope path segments. Looking up the scope here
 * yields a trusted constant literal, so caller-influenced values can never flow
 * into the request URL path (SSRF guard).
 */
const INVENTORY_SCOPE_SEGMENT: Record<InventoryScope, string> = { tenants: "tenants", orgs: "orgs", groups: "groups" };
const INVENTORY_SCOPE_LABEL: Record<InventoryScope, string> = { tenants: "tenant_id", orgs: "org_id", groups: "group_id" };

/** Build the validated `/{scope}/{id}/inventory/assets` base path for a scope. */
function inventoryBase(scope: InventoryScope, scopeId: string): string {
  const safeScope = INVENTORY_SCOPE_SEGMENT[scope];
  if (!safeScope) throw new Error(`Invalid inventory scope: ${String(scope)}`);
  const safeId = sanitizePathSegment(scopeId, INVENTORY_SCOPE_LABEL[scope]);
  return `/${safeScope}/${safeId}/inventory/assets`;
}

/** Attributes accepted by the Inventory Assets PATCH endpoints. */
export interface InventoryAssetAttributes {
  class?: { display_name?: "A" | "B" | "C" | "D"; rank?: 1 | 2 | 3 | 4; locked?: boolean };
  labels?: { add?: string[]; remove?: string[] } | { replace: string[] };
  tags?: { add?: Record<string, string>; remove?: string[] } | { replace: Record<string, string> };
}

/**
 * List or search inventory assets synchronously (Early Access).
 * GET /{scope}/{id}/inventory/assets. Supports an RSQL `filter` expression.
 */
export async function listInventoryAssets(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  opts: { filter?: string; sort?: string; limit?: number; starting_after?: string; ending_before?: string; fields?: string; meta_count?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const qs = buildQuery({
    filter: opts.filter,
    sort: opts.sort,
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    meta_count: opts.meta_count,
    "fields[container_images]": opts.fields,
  });
  const res = await restFetch(config, `${base}${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST listInventoryAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get a single inventory asset by ID (Early Access). GET /{scope}/{id}/inventory/assets/{asset_id}. */
export async function getInventoryAsset(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  assetId: string,
  opts: { fields?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const qs = buildQuery({ "fields[container_images]": opts.fields });
  const res = await restFetch(config, `${base}/${safeAssetId}${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST getInventoryAsset failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Update a single inventory asset's class, labels, and/or tags (Early Access).
 * PATCH /{scope}/{id}/inventory/assets/{asset_id}. Body: { data: { type, id, attributes } }.
 */
export async function updateInventoryAsset(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  assetId: string,
  type: string,
  attributes: InventoryAssetAttributes
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const body = { data: { type, id: safeAssetId, attributes } };
  const res = await restFetch(config, `${base}/${safeAssetId}`, {
    method: "PATCH",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST updateInventoryAsset failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** List projects for an inventory asset (Early Access). GET /{scope}/{id}/inventory/assets/{asset_id}/relationships/projects. */
export async function listInventoryAssetProjects(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  assetId: string,
  opts: { limit?: number; starting_after?: string; ending_before?: string; canonical?: string; target_id?: string; sort?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const qs = buildQuery({
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    canonical: opts.canonical,
    target_id: opts.target_id,
    sort: opts.sort,
  });
  const res = await restFetch(config, `${base}/${safeAssetId}/relationships/projects${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST listInventoryAssetProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** List targets for an inventory asset (Early Access). GET /{scope}/{id}/inventory/assets/{asset_id}/relationships/targets. */
export async function listInventoryAssetTargets(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  assetId: string,
  opts: { limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const qs = buildQuery({ limit: opts.limit, starting_after: opts.starting_after, ending_before: opts.ending_before });
  const res = await restFetch(config, `${base}/${safeAssetId}/relationships/targets${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST listInventoryAssetTargets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * Create an asynchronous inventory asset search (Early Access).
 * POST /{scope}/{id}/inventory/assets/searches. Returns a search resource whose
 * results are fetched via getInventoryAssetSearchResults.
 */
export async function createInventoryAssetSearch(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  attributes: { filter?: string; limit?: number; meta_count?: "with" | "only"; sort?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const body = { data: { type: "searches", attributes } };
  const res = await restFetch(config, `${base}/searches`, {
    method: "POST",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST createInventoryAssetSearch failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Retrieve asynchronous inventory asset search results (Early Access). GET /{scope}/{id}/inventory/assets/searches/{search_id}/results. */
export async function getInventoryAssetSearchResults(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  searchId: string,
  opts: { sort?: string; limit?: number; starting_after?: string; ending_before?: string; fields?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeSearchId = sanitizePathSegment(searchId, "search_id");
  const qs = buildQuery({
    sort: opts.sort,
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    "fields[container_images]": opts.fields,
  });
  const res = await restFetch(config, `${base}/searches/${safeSearchId}/results${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST getInventoryAssetSearchResults failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get available filter fields for inventory assets (Early Access). GET /{scope}/{id}/inventory/assets/filters. */
export async function listInventoryAssetFilters(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  opts: { asset_types?: string; limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const qs = buildQuery({ asset_types: opts.asset_types, limit: opts.limit, starting_after: opts.starting_after, ending_before: opts.ending_before });
  const res = await restFetch(config, `${base}/filters${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST listInventoryAssetFilters failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get filter value suggestions (autocomplete) for a filter field (Early Access). GET /{scope}/{id}/inventory/assets/filters/{filter_id}/values. */
export async function getInventoryAssetFilterValues(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  filterId: string,
  opts: { q?: string; limit?: number; starting_after?: string; ending_before?: string; keys_only?: boolean; key?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeFilterId = sanitizeFieldSegment(filterId, "filter_id");
  const qs = buildQuery({
    q: opts.q,
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    keys_only: opts.keys_only === undefined ? undefined : String(opts.keys_only),
    key: opts.key,
  });
  const res = await restFetch(config, `${base}/filters/${safeFilterId}/values${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST getInventoryAssetFilterValues failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get available group fields for inventory assets (Early Access). GET /{scope}/{id}/inventory/assets/groups. */
export async function listInventoryAssetGroups(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  opts: { asset_types?: string; limit?: number; starting_after?: string; ending_before?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const qs = buildQuery({ asset_types: opts.asset_types, limit: opts.limit, starting_after: opts.starting_after, ending_before: opts.ending_before });
  const res = await restFetch(config, `${base}/groups${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST listInventoryAssetGroups failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Get group value aggregation for a group field (Early Access). GET /{scope}/{id}/inventory/assets/groups/{group_field_id}/values. */
export async function getInventoryAssetGroupValues(
  config: SnykApiConfig,
  scope: InventoryScope,
  scopeId: string,
  groupFieldId: string,
  opts: { asset_types?: string; filter?: string; sort?: string; limit?: number; starting_after?: string; ending_before?: string; meta_fields?: string; aggregate?: string } = {}
): Promise<Record<string, unknown>> {
  const base = inventoryBase(scope, scopeId);
  const safeGroupFieldId = sanitizeFieldSegment(groupFieldId, "group_field_id");
  const qs = buildQuery({
    asset_types: opts.asset_types,
    filter: opts.filter,
    sort: opts.sort,
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    meta_fields: opts.meta_fields,
    aggregate: opts.aggregate,
  });
  const res = await restFetch(config, `${base}/groups/${safeGroupFieldId}/values${qs}`, { version: ASSET_API_VERSION });
  if (!res.ok) throw new Error(`REST getInventoryAssetGroupValues failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}
