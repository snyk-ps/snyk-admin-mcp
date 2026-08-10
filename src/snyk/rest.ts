import { ASSET_API_VERSION, assertAllowedUrl, getBaseUrl, REST_API_VERSION, SECRETS_SETTINGS_API_VERSION, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, restRateLimiter } from "./rateLimit.js";

/**
 * Client for Snyk's REST API (JSON:API). Grouped by area in source order: orgs/projects,
 * per-org settings resources used by snyk_copy_org_settings (SAST, Open Source languages,
 * Secrets), then the Asset API used by snyk_search_assets/snyk_update_assets. Each settings
 * function pair follows the same shape: GET returns a resource, and the corresponding update
 * function takes that resource straight back — never hardcode a resource's `type` or `id`
 * when a caller could instead pass through what a prior GET returned (see the SAST/Secrets
 * settings comments below for why: the source org's `id` silently leaking into a PATCH aimed
 * at a different org was a real bug here once already).
 */

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

/** One page of `GET /orgs`: the orgs themselves plus JSON:API cursor links and an optional total count. */
export type ListOrgsResponse = {
  data: { id: string; attributes?: { name?: string; group_id?: string; slug?: string } }[];
  links?: { next?: string; prev?: string; first?: string; last?: string };
  meta?: { count?: number };
};

/** List organizations visible to the token (REST API). GET /orgs, with cursor pagination and optional filters. */
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

/** Safety cap on pages scanned when searching the accessible org list. */
const MAX_ORG_LOOKUP_PAGES = 50;

/**
 * Get the group_id from the first org the token can access (for accounts that require
 * group_id to create orgs). Stops at the first org that has one, so this almost always
 * costs a single request; it only keeps paging if an entire page is group-less.
 */
export async function getDefaultGroupId(config: SnykApiConfig): Promise<string | null> {
  let cursor: string | undefined;
  for (let page = 0; page < MAX_ORG_LOOKUP_PAGES; page++) {
    const res = await listOrgs(config, { limit: 100, starting_after: cursor });
    const withGroup = (res.data ?? []).find((org) => org.attributes?.group_id);
    if (withGroup) return withGroup.attributes?.group_id ?? null;
    if (!res.links?.next) break;
    cursor = res.links.next;
  }
  return null;
}

/**
 * Org display names are rendered several times per tool call (dry-run text, then the
 * apply confirmation), so memoize them briefly. Only the name is cached, never the set
 * of orgs — a stale entry can show an old name after a rename, but it can never hide an
 * org that was just created. Keyed by org ID alone because a process serves one token.
 */
const ORG_NAME_TTL_MS = 60_000;
const orgNameCache = new Map<string, { name: string | null; at: number }>();

/**
 * Get org display name by org ID (REST API). GET /orgs/{org_id}.
 * Returns null when the org isn't visible to the token so callers can fall back to
 * printing the raw ID; other failures throw, matching how the rest of this client behaves.
 */
export async function getOrgName(config: SnykApiConfig, orgId: string): Promise<string | null> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const cached = orgNameCache.get(safeOrgId);
  if (cached && Date.now() - cached.at < ORG_NAME_TTL_MS) return cached.name;

  const res = await restFetch(config, `/orgs/${safeOrgId}`);
  let name: string | null = null;
  if (res.ok) {
    const body = (await res.json()) as { data?: { attributes?: { name?: string } } };
    name = body.data?.attributes?.name ?? null;
  } else if (res.status !== 404 && res.status !== 403) {
    throw new Error(`REST getOrgName failed: ${res.status} ${await res.text()}`);
  }
  orgNameCache.set(safeOrgId, { name, at: Date.now() });
  return name;
}

/** List projects for an org (REST API). GET /orgs/{org_id}/projects. */
export async function listProjects(
  config: SnykApiConfig,
  orgId: string
): Promise<{ data: { id: string; attributes?: { name?: string } }[] }> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/projects`);
  if (!res.ok) throw new Error(`REST listProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<{ data: { id: string; attributes?: { name?: string } }[] }>;
}

/** One audit log entry, per the OpenAPI spec's `AuditLogSearch.items` shape. */
export type AuditLogEntry = {
  created: string;
  event: string;
  content?: Record<string, unknown>;
  group_id?: string;
  org_id?: string;
  project_id?: string;
};

/** Response shape for both audit-log search endpoints: a page of entries plus cursor links. */
export type AuditLogSearchResponse = {
  data: { type: string; items: AuditLogEntry[] };
  links?: { next?: string; prev?: string; first?: string; last?: string };
};

/**
 * Search audit logs for an org or group (REST API, JSON:API, GA/stable). GET
 * /orgs/{org_id}/audit_logs/search or GET /groups/{group_id}/audit_logs/search — same shape
 * either way, only the scope segment differs. Per Snyk's spec, "api.access" events are
 * omitted from results unless explicitly requested via `events` — that's the API's own
 * default, not something added here.
 */
export async function searchAuditLogs(
  config: SnykApiConfig,
  scope: "orgs" | "groups",
  scopeId: string,
  opts: {
    from?: string;
    to?: string;
    events?: string[];
    exclude_events?: string[];
    user_id?: string;
    project_id?: string;
    size?: number;
    sort_order?: "ASC" | "DESC";
    cursor?: string;
  } = {}
): Promise<AuditLogSearchResponse> {
  const safeId = sanitizePathSegment(scopeId, scope === "orgs" ? "org_id" : "group_id");
  // Not using buildQuery here: `events`/`exclude_events` are repeated-key array params
  // (?events=a&events=b), which buildQuery's single-value-per-key model doesn't support.
  const search = new URLSearchParams();
  if (opts.from) search.append("from", opts.from);
  if (opts.to) search.append("to", opts.to);
  for (const e of opts.events ?? []) search.append("events", e);
  for (const e of opts.exclude_events ?? []) search.append("exclude_events", e);
  if (opts.user_id) search.append("user_id", opts.user_id);
  if (opts.project_id) search.append("project_id", opts.project_id);
  if (opts.size !== undefined) search.append("size", String(opts.size));
  if (opts.sort_order) search.append("sort_order", opts.sort_order);
  if (opts.cursor) search.append("cursor", opts.cursor);
  const qs = search.toString();
  const res = await restFetch(config, `/${scope}/${safeId}/audit_logs/search${qs ? `?${qs}` : ""}`);
  if (!res.ok) throw new Error(`REST searchAuditLogs failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<AuditLogSearchResponse>;
}

/**
 * The org SAST settings resource. `sast_enabled` is the only writable attribute — the PATCH
 * schema declares it as the sole property with `additionalProperties: false`. `autofix_enabled`
 * still appears (optional) in the GET response schema but is read-only here: that control is
 * now Snyk Agent Fix, configured separately under Settings > Snyk Agent Fix at group or org
 * level. Anything beyond `sast_enabled` must be dropped before PATCHing.
 */
export type SastSettingsResource = {
  type: string;
  attributes: { sast_enabled?: boolean } & Record<string, unknown>;
};

/** Get SAST settings for an org (REST API, JSON:API). GET /orgs/{org_id}/settings/sast. */
export async function getSastSettings(config: SnykApiConfig, orgId: string): Promise<SastSettingsResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/sast`);
  if (!res.ok) throw new Error(`REST getSastSettings failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: SastSettingsResource };
  return body.data;
}

/**
 * Update SAST settings for an org (REST API, JSON:API). PATCH /orgs/{org_id}/settings/sast.
 * Pass the `type`/`attributes` straight from getSastSettings rather than a hardcoded type,
 * since the exact JSON:API resource type string isn't documented in Snyk's public reference.
 */
export async function updateSastSettings(
  config: SnykApiConfig,
  orgId: string,
  resource: SastSettingsResource
): Promise<SastSettingsResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  if (typeof resource.attributes.sast_enabled !== "boolean") {
    throw new Error("Cannot update SAST settings: source settings are missing a boolean sast_enabled");
  }
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/sast`, {
    method: "PATCH",
    // Build the body field by field rather than echoing the GET response. Two separate traps:
    // `id` is required and must be the *target* org (the fetched object carries the source
    // org's id at runtime even though the TS type omits it), and the PATCH schema accepts only
    // `sast_enabled` with `additionalProperties: false` — forwarding a read-only attribute such
    // as `autofix_enabled` would 400 on any org whose GET returns it.
    body: JSON.stringify({
      data: {
        type: resource.type,
        id: safeOrgId,
        attributes: { sast_enabled: resource.attributes.sast_enabled },
      },
    }),
  });
  if (!res.ok) throw new Error(`REST updateSastSettings failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: SastSettingsResource };
  return body.data;
}

/**
 * Languages the Open Source settings API accepts as a `{language}` path segment.
 * Looking a caller-supplied value up against this allowlist yields a trusted literal,
 * so nothing caller-influenced can reach the URL path (SSRF guard).
 */
const OPEN_SOURCE_LANGUAGES = ["javascript", "python", "dotnet", "php", "golang", "java"] as const;

/** Per-language package-manager settings, keyed by language (e.g. `{ javascript: { npm: {...} } }`). */
export type LanguageSettingsMap = Record<string, Record<string, unknown>>;

/** The single `languages_settings` resource the collection GET returns. */
export type LanguageSettingsResource = {
  id: string;
  type: string;
  attributes: { languages?: LanguageSettingsMap };
};

/**
 * Get Open Source language settings for an org (REST API, JSON:API).
 * GET /orgs/{org_id}/settings/open_source/languages. Despite the plural path this returns a
 * single `languages_settings` resource whose `attributes.languages` is a map of language ->
 * package-manager settings, not a list of per-language resources.
 */
export async function getLanguageSettings(config: SnykApiConfig, orgId: string): Promise<LanguageSettingsResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/open_source/languages`);
  if (!res.ok) throw new Error(`REST getLanguageSettings failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: LanguageSettingsResource };
  return body.data;
}

/**
 * Update one language's Open Source settings for an org (REST API, JSON:API).
 * PATCH /orgs/{org_id}/settings/open_source/languages/{language}, one call per language.
 * Body is `{ data: { type: "language_settings", id, attributes: { package_managers } } }` —
 * note the response type is `languages_settings` (plural) but the update type is singular.
 */
export async function updateLanguageSettings(
  config: SnykApiConfig,
  orgId: string,
  language: string,
  packageManagers: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeLanguage = OPEN_SOURCE_LANGUAGES.find((l) => l === language);
  if (!safeLanguage) {
    throw new Error(`Unsupported Open Source language "${language}" (expected one of: ${OPEN_SOURCE_LANGUAGES.join(", ")})`);
  }
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/open_source/languages/${safeLanguage}`, {
    method: "PATCH",
    // `id` is required and must identify the org being written to — never the org the
    // settings were read from, or this silently targets the wrong org.
    body: JSON.stringify({
      data: { type: "language_settings", id: safeOrgId, attributes: { package_managers: packageManagers } },
    }),
  });
  if (!res.ok) throw new Error(`REST updateLanguageSettings failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as Record<string, unknown>;
}

/**
 * A SecretsEnablement resource, per Snyk's OpenAPI spec (`components.schemas.SecretsEnablement`):
 * `{ type, id: <org_id>, attributes: { secrets_enabled: boolean } }`. Early Access / beta.
 * `attributes` is typed loosely (`secrets_enabled` optional, plus an escape hatch for
 * unknown fields) rather than trusting the spec's `additionalProperties: false` to hold at
 * runtime — the same assumption for SAST settings' GET response didn't (see updateSastSettings).
 */
export type SecretsSettingsResource = {
  id: string;
  type: string;
  attributes: { secrets_enabled?: boolean } & Record<string, unknown>;
};

/**
 * Get Secrets settings for an org (REST API, JSON:API, Early Access/beta).
 * GET /orgs/{org_id}/settings/secrets. Confirmed from Snyk's OpenAPI spec — this resource is
 * only released under the `2024-10-15~beta` version, not the plain dated version used elsewhere.
 */
export async function getSecretsSettings(config: SnykApiConfig, orgId: string): Promise<SecretsSettingsResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/secrets`, { version: SECRETS_SETTINGS_API_VERSION });
  if (!res.ok) throw new Error(`REST getSecretsSettings failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: SecretsSettingsResource };
  return body.data;
}

/**
 * Update Secrets settings for an org (REST API, JSON:API, Early Access/beta).
 * PATCH /orgs/{org_id}/settings/secrets. Per the OpenAPI spec, the request body requires
 * `id` to identify the org being updated — always the target org's id, never the source
 * org's (the same mistake that was previously caught and fixed for SAST settings).
 */
export async function updateSecretsSettings(
  config: SnykApiConfig,
  orgId: string,
  resource: SecretsSettingsResource
): Promise<SecretsSettingsResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  if (typeof resource.attributes.secrets_enabled !== "boolean") {
    throw new Error("Cannot update Secrets settings: source settings are missing a boolean secrets_enabled");
  }
  const res = await restFetch(config, `/orgs/${safeOrgId}/settings/secrets`, {
    method: "PATCH",
    version: SECRETS_SETTINGS_API_VERSION,
    // Build the body field by field rather than echoing the GET response — same precaution
    // already proven necessary for SAST settings: `id` must be the *target* org (the fetched
    // object carries the source org's id at runtime even though it shouldn't be relied on),
    // and only `secrets_enabled` is forwarded, so any other field a live GET happens to
    // return can't ride along into a PATCH the way `autofix_enabled` did for SAST.
    body: JSON.stringify({
      data: {
        id: safeOrgId,
        type: resource.type,
        attributes: { secrets_enabled: resource.attributes.secrets_enabled },
      },
    }),
  });
  if (!res.ok) throw new Error(`REST updateSecretsSettings failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: SecretsSettingsResource };
  return body.data;
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
