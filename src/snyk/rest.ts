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

/** Safety cap on pages scanned when resolving an org across the full accessible list. */
const MAX_ORG_LOOKUP_PAGES = 50;

/** Fetch every org the token can see, paginating with a large page size up to a safety cap. */
async function listAllOrgs(config: SnykApiConfig): Promise<ListOrgsResponse["data"]> {
  const all: ListOrgsResponse["data"] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_ORG_LOOKUP_PAGES; page++) {
    const res = await listOrgs(config, { limit: 100, starting_after: cursor });
    all.push(...(res.data ?? []));
    if (!res.links?.next) break;
    cursor = res.links.next;
  }
  return all;
}

/** Get the group_id from the first org the token can access (for accounts that require group_id to create orgs). */
export async function getDefaultGroupId(config: SnykApiConfig): Promise<string | null> {
  const orgs = await listAllOrgs(config);
  const firstWithGroup = orgs.find((org) => org.attributes?.group_id);
  return firstWithGroup?.attributes?.group_id ?? null;
}

/** Get org display name by org ID (from listOrgs, scanning all pages). Returns null if not found. */
export async function getOrgName(config: SnykApiConfig, orgId: string): Promise<string | null> {
  const orgs = await listAllOrgs(config);
  const org = orgs.find((o) => o.id === orgId);
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
// Asset API (Early Access). Group-scoped asset search, lookup, and update.
// Uses ASSET_API_VERSION.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/asset
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Inventory Assets API (Early Access). Only the bulk-update endpoint is kept —
// it's the one genuine server-side bulk labeling operation across the tools
// this server exposes (the Asset API above only updates one asset per call,
// and V1 project tags has no bulk endpoint at all). The rest of the Inventory
// Assets API surface (list/get/relationships/search/filters/groups, tenant and
// group scoping) was intentionally dropped as redundant with the Asset API.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/inventory-assets
// ---------------------------------------------------------------------------

/** Bulk update inventory assets (Early Access). PATCH /orgs/{org_id}/inventory/assets. Body: JSON:API data array with type "asset", id, and attributes (class, labels, tags). */
export async function bulkUpdateInventoryAssets(
  config: SnykApiConfig,
  orgId: string,
  body: { data: Array<{ type: string; id: string; attributes: { class?: string; labels?: string[]; tags?: Record<string, string> } }> }
): Promise<Record<string, unknown>> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/inventory/assets`, {
    method: "PATCH",
    body: JSON.stringify(body),
    version: ASSET_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST bulkUpdateInventoryAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}
