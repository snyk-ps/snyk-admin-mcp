import { ASSET_API_VERSION, assertAllowedUrl, getBaseUrl, REST_API_VERSION, sanitizePathSegment, type SnykApiConfig } from "./types.js";
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

export async function listOrgs(config: SnykApiConfig): Promise<{ data: { id: string; attributes?: { name?: string; group_id?: string } }[] }> {
  const res = await restFetch(config, "/orgs");
  if (!res.ok) throw new Error(`REST listOrgs failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<{ data: { id: string; attributes?: { name?: string; group_id?: string } }[] }>;
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
