import { ASSET_API_VERSION, assertAllowedUrl, getBaseUrl, POLICIES_API_VERSION, REST_API_VERSION, SECRETS_SETTINGS_API_VERSION, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, restRateLimiter } from "./rateLimit.js";

/**
 * Client for Snyk's REST API (JSON:API). Grouped by area in source order: orgs/projects,
 * per-org settings resources used by snyk_copy_org_settings (SAST, Open Source languages,
 * Secrets), the Asset API used by snyk_search_assets/snyk_update_assets, then Collections
 * (org-scoped project groupings) used by the snyk_*_collection* tools. Each settings
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
    // links.next is a whole relative URL; only its starting_after value is a cursor.
    const next = cursorFromLink(res.links?.next, "starting_after");
    if (!next) break;
    cursor = next;
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

/** Project attributes that classify a project. Each is a list; a PATCH replaces the whole list. */
export const PROJECT_BUSINESS_CRITICALITY = ["critical", "high", "medium", "low"] as const;
export const PROJECT_ENVIRONMENT = ["frontend", "backend", "internal", "external", "mobile", "saas", "onprem", "hosted", "distributed"] as const;
export const PROJECT_LIFECYCLE = ["production", "development", "sandbox"] as const;
export const PROJECT_TEST_FREQUENCY = ["daily", "weekly", "never"] as const;

/** One project from `GET /orgs/{org_id}/projects` (only the fields this server reads). */
export type ProjectResource = {
  id: string;
  type?: string;
  attributes?: {
    name?: string;
    type?: string;
    target_file?: string;
    target_reference?: string;
    origin?: string;
    created?: string;
    status?: string;
    business_criticality?: string[];
    environment?: string[];
    lifecycle?: string[];
    tags?: { key: string; value: string }[];
    settings?: { recurring_tests?: { frequency?: string } };
  } & Record<string, unknown>;
  relationships?: {
    target?: { data?: { id?: string } };
    owner?: { data?: { id?: string } | null };
  } & Record<string, unknown>;
  meta?: { latest_issue_counts?: { critical?: number; high?: number; medium?: number; low?: number } } & Record<string, unknown>;
};
export type ListProjectsResponse = { data: ProjectResource[]; links?: PageLinks; meta?: { count?: number } };

/** Filters and paging for listProjects. Array filters are sent comma-separated (`style: form, explode: false`). */
export type ListProjectsOptions = {
  limit?: number;
  starting_after?: string;
  ending_before?: string;
  ids?: string[];
  names?: string[];
  names_start_with?: string[];
  origins?: string[];
  types?: string[];
  target_id?: string[];
  target_reference?: string;
  /** "key:value" strings; a project must have every one. */
  tags?: string[];
  business_criticality?: string[];
  environment?: string[];
  lifecycle?: string[];
  latest_issue_counts?: boolean;
  count_only?: boolean;
};

/** List projects for an org (REST API). GET /orgs/{org_id}/projects, with filters and cursor paging. */
export async function listProjects(config: SnykApiConfig, orgId: string, opts: ListProjectsOptions = {}): Promise<ListProjectsResponse> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const search = new URLSearchParams();
  const csv = (key: string, values?: string[]) => { if (values?.length) search.append(key, values.join(",")); };
  csv("ids", opts.ids);
  csv("names", opts.names);
  csv("names_start_with", opts.names_start_with);
  csv("origins", opts.origins);
  csv("types", opts.types);
  csv("tags", opts.tags);
  csv("business_criticality", opts.business_criticality);
  csv("environment", opts.environment);
  csv("lifecycle", opts.lifecycle);
  // target_id is the one array filter without `explode: false`, so it's a repeated key.
  for (const t of opts.target_id ?? []) search.append("target_id", t);
  if (opts.target_reference) search.append("target_reference", opts.target_reference);
  if (opts.latest_issue_counts) search.append("meta.latest_issue_counts", "true");
  if (opts.count_only) search.append("meta_count", "only");
  if (opts.limit !== undefined) search.append("limit", String(opts.limit));
  if (opts.starting_after) search.append("starting_after", opts.starting_after);
  if (opts.ending_before) search.append("ending_before", opts.ending_before);
  const qs = encodeQuery(search);
  const res = await restFetch(config, `/orgs/${safeOrgId}/projects${qs ? `?${qs}` : ""}`);
  if (!res.ok) throw new Error(`REST listProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListProjectsResponse>;
}

/** The `ids` filter is sent in the URL, so look IDs up in batches of this many (also the max page size). */
const PROJECT_LOOKUP_BATCH = 100;
/** 8-4-4-4-12 hex, any version — the shape every Snyk project ID has. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Look up projects by ID in one org: returns the ones found (keyed by lowercase ID) and the IDs
 * that aren't in that org. Used by dry runs so a typo or a project from another org is caught
 * before an approval token is issued, rather than failing part-way through the apply.
 */
export async function findProjectsByIds(
  config: SnykApiConfig,
  orgId: string,
  ids: string[]
): Promise<{ found: Map<string, ProjectResource>; missing: string[] }> {
  const found = new Map<string, ProjectResource>();
  // Project IDs are UUIDs, and the `ids` filter is `format: uuid`: a single malformed ID makes
  // the whole lookup 400 ("Parameter 'ids' must be url encoded", verified live) instead of naming
  // it. So malformed IDs aren't sent; they come back as missing, by name, like any unknown ID.
  const unique = [...new Set(ids.map((id) => id.toLowerCase()))].filter((id) => UUID_PATTERN.test(id));
  for (let i = 0; i < unique.length; i += PROJECT_LOOKUP_BATCH) {
    const batch = unique.slice(i, i + PROJECT_LOOKUP_BATCH);
    const page = await listProjects(config, orgId, { ids: batch, limit: PROJECT_LOOKUP_BATCH });
    for (const p of page.data ?? []) found.set(p.id.toLowerCase(), p);
  }
  return { found, missing: ids.filter((id) => !found.has(id.toLowerCase())) };
}

/** What snyk_update_projects can change. Omitted fields are left as they are. */
export type ProjectUpdate = {
  business_criticality?: string[];
  environment?: string[];
  lifecycle?: string[];
  test_frequency?: string;
  /** A user ID to set the owner, or null to clear it. Omit to leave the owner unchanged. */
  owner_user_id?: string | null;
};

/**
 * Update one project's attributes and/or owner (REST API, GA). PATCH /orgs/{org_id}/projects/{project_id}.
 * Each attribute list replaces the project's current list. Tags are deliberately not sent here:
 * the same PATCH would replace every tag, and the add/remove tag tools already cover tags.
 */
export async function updateProject(config: SnykApiConfig, orgId: string, projectId: string, update: ProjectUpdate): Promise<ProjectResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeProjectId = sanitizePathSegment(projectId, "project_id");
  const attributes: Record<string, unknown> = {};
  if (update.business_criticality !== undefined) attributes.business_criticality = update.business_criticality;
  if (update.environment !== undefined) attributes.environment = update.environment;
  if (update.lifecycle !== undefined) attributes.lifecycle = update.lifecycle;
  if (update.test_frequency !== undefined) attributes.test_frequency = update.test_frequency;
  // The spec makes `relationships` required on the body; it's sent empty unless the owner changes.
  const relationships: Record<string, unknown> = {};
  if (update.owner_user_id !== undefined) relationships.owner = { data: { type: "user", id: update.owner_user_id } };
  const res = await restFetch(config, `/orgs/${safeOrgId}/projects/${safeProjectId}`, {
    method: "PATCH",
    body: JSON.stringify({ data: { type: "project", id: safeProjectId, attributes, relationships } }),
  });
  if (!res.ok) throw new Error(`REST updateProject failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: ProjectResource };
  return body.data;
}

// --- Memberships (GA): who is in an org or group, and with which role ---

/** One membership. The API embeds the user's name/email and the role's name in `relationships`. */
export type MembershipResource = {
  id: string;
  type?: string;
  attributes?: { created_at?: string } & Record<string, unknown>;
  relationships?: {
    user?: { data?: { id?: string; attributes?: { name?: string; email?: string; username?: string; login_method?: string } } };
    role?: { data?: { id?: string; attributes?: { name?: string } } };
  } & Record<string, unknown>;
};
export type ListMembershipsResponse = { data: MembershipResource[]; links?: PageLinks; meta?: Record<string, unknown> };

/**
 * List memberships of an org or group. GET /orgs/{org_id}/memberships or /groups/{group_id}/memberships.
 * `sort_by: "role"` is translated per scope: the org endpoint calls the column `role`, the
 * group endpoint `role_name`.
 */
export async function listMemberships(
  config: SnykApiConfig,
  scope: "orgs" | "groups",
  scopeId: string,
  opts: {
    email?: string;
    username?: string;
    user_id?: string;
    role_name?: string;
    sort_by?: "username" | "user_display_name" | "email" | "login_method" | "role";
    sort_order?: "ASC" | "DESC";
    limit?: number;
    starting_after?: string;
    ending_before?: string;
  } = {}
): Promise<ListMembershipsResponse> {
  const safeId = sanitizePathSegment(scopeId, scope === "orgs" ? "org_id" : "group_id");
  const sortBy = opts.sort_by === "role" && scope === "groups" ? "role_name" : opts.sort_by;
  const qs = buildQuery({
    email: opts.email,
    username: opts.username,
    user_id: opts.user_id,
    role_name: opts.role_name,
    sort_by: sortBy,
    sort_order: opts.sort_order,
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
  });
  const res = await restFetch(config, `/${scope}/${safeId}/memberships${qs}`);
  if (!res.ok) throw new Error(`REST listMemberships failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListMembershipsResponse>;
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
  const qs = encodeQuery(search);
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
  const qs = encodeQuery(search);
  return qs ? `?${qs}` : "";
}

/**
 * Serialize query params with spaces as %20. URLSearchParams writes a space as `+`, and some
 * Snyk endpoints reject that: GET /orgs/{id}/collections?name=a+b answers 400 "Parameter 'name'
 * must be url encoded" (verified live), so a collection name with a space couldn't be searched
 * or created. A literal `+` in a value is already written as %2B, so every `+` here is a space.
 */
export function encodeQuery(search: URLSearchParams): string {
  return search.toString().replace(/\+/g, "%20");
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

/** An asset's type and name, or null when the group has no asset with this ID (404). Used to check IDs in dry runs. */
export async function findAsset(
  config: SnykApiConfig,
  groupId: string,
  assetId: string
): Promise<{ id: string; type: string; name: string | null } | null> {
  const safeGroupId = sanitizePathSegment(groupId, "group_id");
  const safeAssetId = sanitizePathSegment(assetId, "asset_id");
  const res = await restFetch(config, `/groups/${safeGroupId}/assets/${safeAssetId}`, { version: ASSET_API_VERSION });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`REST getAsset failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data?: { id?: string; type?: string; attributes?: { name?: string } } };
  return { id: body.data?.id ?? safeAssetId, type: body.data?.type ?? "unknown", name: body.data?.attributes?.name ?? null };
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
// Collections (GA since 2023-09-12, served under the default REST_API_VERSION).
// Org-scoped named groupings of projects — there is no group-level endpoint.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/collection
// ---------------------------------------------------------------------------

/** The add/remove-projects endpoints reject bodies with more than this many project IDs (`maxItems: 100` in the spec). */
export const COLLECTION_PROJECTS_MAX_PER_REQUEST = 100;

/** Allowed collection name characters, copied from the spec's create/edit `name` pattern (1-255 chars). */
export const COLLECTION_NAME_PATTERN = /^[a-zA-Z0-9 _\-/:.]+$/;

/**
 * One collection. `is_generated` collections are created and maintained by Snyk itself —
 * live data shows one per imported repository, named after it (e.g. `github.com/org/repo`),
 * with a null `created_by_user`. `meta` is only present on list responses.
 */
export type CollectionResource = {
  id: string;
  type: string;
  attributes: { name: string; is_generated?: boolean };
  meta?: {
    projects_count: number;
    issues_critical_count: number;
    issues_high_count: number;
    issues_medium_count: number;
    issues_low_count: number;
  };
  relationships?: {
    created_by_user?: { data: { type: string; id: string | null } };
    org?: { data: { type: string; id: string } };
  };
};

/** JSON:API cursor links. `next`/`prev` are relative paths (e.g. `/rest/orgs/...?starting_after=...`), not bare cursors. */
export type PageLinks = { self?: string; next?: string; prev?: string; first?: string; last?: string };

export type ListCollectionsResponse = { data: CollectionResource[]; links?: PageLinks };

/** One project in a collection. The API returns IDs and issue counts only — no project names. */
export type CollectionProject = {
  id: string;
  type: string;
  meta: {
    imported: string;
    last_tested_at: string;
    issues_critical_count: number;
    issues_high_count: number;
    issues_medium_count: number;
    issues_low_count: number;
  };
  relationships: { target: { data: { type: string; id: string } } };
};

export type ListCollectionProjectsResponse = { data: CollectionProject[]; links?: PageLinks };

/**
 * Pull a cursor query param out of a JSON:API link: `starting_after` / `ending_before` for
 * most list endpoints, `cursor` for audit-log search. Snyk's `links.next` is a full relative
 * URL, so handing it back verbatim as the cursor sends the whole path as its value — the
 * audit-log API answers that with 400 "invalid cursor" (verified live).
 */
export function cursorFromLink(
  link: string | undefined,
  param: "starting_after" | "ending_before" | "cursor"
): string | null {
  if (!link) return null;
  try {
    return new URL(link, "https://placeholder.invalid").searchParams.get(param);
  } catch {
    return null;
  }
}

/** List collections in an org. GET /orgs/{org_id}/collections, with filters, sort, and cursor pagination. */
export async function listCollections(
  config: SnykApiConfig,
  orgId: string,
  opts: {
    limit?: number;
    starting_after?: string;
    ending_before?: string;
    sort?: "name" | "projectsCount" | "issues";
    direction?: "ASC" | "DESC";
    name?: string;
    is_generated?: boolean;
  } = {}
): Promise<ListCollectionsResponse> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const qs = buildQuery({
    limit: opts.limit,
    starting_after: opts.starting_after,
    ending_before: opts.ending_before,
    sort: opts.sort,
    direction: opts.direction,
    name: opts.name,
    is_generated: opts.is_generated === undefined ? undefined : String(opts.is_generated),
  });
  const res = await restFetch(config, `/orgs/${safeOrgId}/collections${qs}`);
  if (!res.ok) throw new Error(`REST listCollections failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListCollectionsResponse>;
}

/** Get one collection. GET /orgs/{org_id}/collections/{collection_id}. */
export async function getCollection(config: SnykApiConfig, orgId: string, collectionId: string): Promise<CollectionResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeCollectionId = sanitizePathSegment(collectionId, "collection_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/collections/${safeCollectionId}`);
  if (!res.ok) throw new Error(`REST getCollection failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: CollectionResource };
  return body.data;
}

/** Throws client-side, before any request, if a name would fail the API's own length/pattern check. */
function assertValidCollectionName(name: string): void {
  if (name.length < 1 || name.length > 255 || !COLLECTION_NAME_PATTERN.test(name)) {
    throw new Error(
      `Invalid collection name "${name}": must be 1-255 characters of letters, digits, spaces, or _ - / : .`
    );
  }
}

/** Create an empty collection. POST /orgs/{org_id}/collections. Requires org.collection.create. */
export async function createCollection(config: SnykApiConfig, orgId: string, name: string): Promise<CollectionResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  assertValidCollectionName(name);
  const res = await restFetch(config, `/orgs/${safeOrgId}/collections`, {
    method: "POST",
    body: JSON.stringify({ data: { type: "collection", attributes: { name } } }),
  });
  if (!res.ok) throw new Error(`REST createCollection failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: CollectionResource };
  return body.data;
}

/** Rename a collection — `name` is the only editable attribute. PATCH /orgs/{org_id}/collections/{collection_id}. Requires org.collection.edit. */
export async function renameCollection(
  config: SnykApiConfig,
  orgId: string,
  collectionId: string,
  name: string
): Promise<CollectionResource> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeCollectionId = sanitizePathSegment(collectionId, "collection_id");
  assertValidCollectionName(name);
  const res = await restFetch(config, `/orgs/${safeOrgId}/collections/${safeCollectionId}`, {
    method: "PATCH",
    body: JSON.stringify({ data: { type: "collection", id: safeCollectionId, attributes: { name } } }),
  });
  if (!res.ok) throw new Error(`REST renameCollection failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: CollectionResource };
  return body.data;
}

/**
 * List the projects in a collection. GET /orgs/{org_id}/collections/{collection_id}/relationships/projects.
 * Array filters are sent as repeated keys (OpenAPI's default form/explode encoding).
 */
export async function listCollectionProjects(
  config: SnykApiConfig,
  orgId: string,
  collectionId: string,
  opts: {
    limit?: number;
    starting_after?: string;
    ending_before?: string;
    sort?: "imported" | "last_tested_at" | "issues";
    direction?: "ASC" | "DESC";
    target_id?: string[];
    show?: ("vuln-groups" | "clean-groups")[];
    integration?: string[];
  } = {}
): Promise<ListCollectionProjectsResponse> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeCollectionId = sanitizePathSegment(collectionId, "collection_id");
  const search = new URLSearchParams();
  if (opts.limit !== undefined) search.append("limit", String(opts.limit));
  if (opts.starting_after) search.append("starting_after", opts.starting_after);
  if (opts.ending_before) search.append("ending_before", opts.ending_before);
  if (opts.sort) search.append("sort", opts.sort);
  if (opts.direction) search.append("direction", opts.direction);
  for (const t of opts.target_id ?? []) search.append("target_id", t);
  for (const s of opts.show ?? []) search.append("show", s);
  for (const i of opts.integration ?? []) search.append("integration", i);
  const qs = encodeQuery(search);
  const res = await restFetch(
    config,
    `/orgs/${safeOrgId}/collections/${safeCollectionId}/relationships/projects${qs ? `?${qs}` : ""}`
  );
  if (!res.ok) throw new Error(`REST listCollectionProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListCollectionProjectsResponse>;
}

/**
 * Add (POST) or remove (DELETE) up to 100 projects in one request.
 * /orgs/{org_id}/collections/{collection_id}/relationships/projects. Returns 204 on success.
 * Callers with more than 100 IDs must chunk — this throws rather than silently truncating.
 */
async function changeCollectionProjects(
  config: SnykApiConfig,
  method: "POST" | "DELETE",
  orgId: string,
  collectionId: string,
  projectIds: string[]
): Promise<void> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const safeCollectionId = sanitizePathSegment(collectionId, "collection_id");
  if (projectIds.length === 0) return;
  if (projectIds.length > COLLECTION_PROJECTS_MAX_PER_REQUEST) {
    throw new Error(`At most ${COLLECTION_PROJECTS_MAX_PER_REQUEST} project IDs per request (got ${projectIds.length}); chunk the list.`);
  }
  const data = projectIds.map((id) => ({ type: "project", id: sanitizePathSegment(id, "project_id") }));
  const res = await restFetch(config, `/orgs/${safeOrgId}/collections/${safeCollectionId}/relationships/projects`, {
    method,
    body: JSON.stringify({ data }),
  });
  if (!res.ok) {
    const verb = method === "POST" ? "addProjectsToCollection" : "removeProjectsFromCollection";
    throw new Error(`REST ${verb} failed: ${res.status} ${await res.text()}`);
  }
}

/** Add up to 100 projects to a collection. Requires org.collection.edit. */
export function addProjectsToCollection(config: SnykApiConfig, orgId: string, collectionId: string, projectIds: string[]): Promise<void> {
  return changeCollectionProjects(config, "POST", orgId, collectionId, projectIds);
}

/** Remove up to 100 projects from a collection. Requires org.collection.edit. */
export function removeProjectsFromCollection(config: SnykApiConfig, orgId: string, collectionId: string, projectIds: string[]): Promise<void> {
  return changeCollectionProjects(config, "DELETE", orgId, collectionId, projectIds);
}

/** Safety cap when paging through a collection's members (100 per page → 10,000 projects). */
const MAX_COLLECTION_MEMBER_PAGES = 100;

/**
 * Every project ID in a collection, following cursor pagination at 100 per page.
 * Used to verify add/remove results: those endpoints return 204 even for IDs they ignore.
 */
export async function listAllCollectionProjectIds(config: SnykApiConfig, orgId: string, collectionId: string): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_COLLECTION_MEMBER_PAGES; page++) {
    const res = await listCollectionProjects(config, orgId, collectionId, { limit: 100, starting_after: cursor });
    for (const p of res.data ?? []) ids.push(p.id);
    const next = cursorFromLink(res.links?.next, "starting_after");
    if (!next) return ids;
    cursor = next;
  }
  throw new Error(`Collection has more than ${MAX_COLLECTION_MEMBER_PAGES * 100} projects; stopped paging.`);
}

// ---------------------------------------------------------------------------
// Org-level Policies (GA since 2026-03-25): Snyk Code consistent ignores.
// Each policy ignores one Snyk Code finding across a repository, matched by the finding's
// repository-level ID (`snyk/asset/finding/v1`). Only usable in orgs with "Ignores across the
// repository for Snyk Code" (consistent ignores) turned on.
// Docs: https://docs.snyk.io/developer-tools/snyk-api/reference/policies
// ---------------------------------------------------------------------------

export const IGNORE_TYPES = ["wont-fix", "temporary-ignore", "not-vulnerable"] as const;
export const POLICY_REVIEW_STATES = ["pending", "approved", "rejected", "not-required"] as const;

/** What a policy does and what it matches. These are the fields a create request takes. */
export type IgnorePolicyContent = {
  name: string;
  action_type: "ignore";
  action: { data: { ignore_type: (typeof IGNORE_TYPES)[number]; expires?: string; reason?: string } };
  conditions_group: { logical_operator: "and"; conditions: { field: string; operator: string; value: string }[] };
};

export type IgnorePolicy = {
  id: string;
  type?: string;
  attributes: IgnorePolicyContent & {
    review?: (typeof POLICY_REVIEW_STATES)[number];
    created_at?: string;
    updated_at?: string;
    created_by?: { name?: string; email?: string; id?: string };
  } & Record<string, unknown>;
};
export type ListIgnorePoliciesResponse = { data: IgnorePolicy[]; links?: PageLinks };

export type ListIgnorePoliciesOptions = {
  search?: string;
  review?: string[];
  expires_before?: string;
  expires_after?: string;
  expires_never?: boolean;
  order_by?: "created" | "expires" | "ignore-type" | "requested-by";
  order_direction?: "asc" | "desc";
  limit?: number;
  starting_after?: string;
};

/** One page of an org's ignore policies. GET /orgs/{org_id}/policies. `review` is comma-separated (`explode: false`). */
export async function listIgnorePolicies(config: SnykApiConfig, orgId: string, opts: ListIgnorePoliciesOptions = {}): Promise<ListIgnorePoliciesResponse> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const qs = buildQuery({
    search: opts.search,
    review: opts.review?.length ? opts.review.join(",") : undefined,
    expires_before: opts.expires_before,
    expires_after: opts.expires_after,
    expires_never: opts.expires_never === undefined ? undefined : String(opts.expires_never),
    order_by: opts.order_by,
    order_direction: opts.order_direction,
    limit: opts.limit,
    starting_after: opts.starting_after,
  });
  const res = await restFetch(config, `/orgs/${safeOrgId}/policies${qs}`, { version: POLICIES_API_VERSION });
  if (!res.ok) throw new Error(`REST listIgnorePolicies failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<ListIgnorePoliciesResponse>;
}

/** Safety cap when reading every policy in an org: 50 pages of 100. */
const MAX_POLICY_PAGES = 50;

/** Every ignore policy in an org, following cursors at 100 per page. Throws if there are more than the cap. */
export async function listAllIgnorePolicies(config: SnykApiConfig, orgId: string): Promise<IgnorePolicy[]> {
  const out: IgnorePolicy[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_POLICY_PAGES; page++) {
    const res = await listIgnorePolicies(config, orgId, { limit: 100, starting_after: cursor });
    out.push(...(res.data ?? []));
    const next = cursorFromLink(res.links?.next, "starting_after");
    if (!next) return out;
    cursor = next;
  }
  throw new Error(`Org ${orgId} has more than ${MAX_POLICY_PAGES * 100} ignore policies; this tool stops there rather than work from a partial list.`);
}

/** Create one ignore policy. POST /orgs/{org_id}/policies (201). */
export async function createIgnorePolicy(config: SnykApiConfig, orgId: string, content: IgnorePolicyContent): Promise<IgnorePolicy> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/policies`, {
    method: "POST",
    body: JSON.stringify({
      data: {
        type: "policy",
        attributes: {
          name: content.name,
          action_type: content.action_type,
          action: content.action,
          conditions_group: content.conditions_group,
          source: "api",
        },
      },
    }),
    version: POLICIES_API_VERSION,
  });
  if (!res.ok) throw new Error(`REST createIgnorePolicy failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { data: IgnorePolicy };
  return body.data;
}
