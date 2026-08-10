import { assertAllowedUrl, getBaseUrl, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, v1RateLimiter } from "./rateLimit.js";

/**
 * Client for Snyk's V1 API — org settings, integration listing/cloning, and project tags.
 * Everything here predates the REST/JSON:API surface in rest.ts; use this module only for
 * the specific things V1 still does that REST doesn't (see README.md's Notes and NOTES.md's
 * "V1 org API notes" for which tools rely on which).
 */

/**
 * Snyk V1 API. Use for: org settings, integrations (clone), project tags/labels.
 * Rate-limited to stay under 2000/min; retries on 429.
 * Docs: https://docs.snyk.io/snyk-api/v1-api
 */
export async function v1Fetch(
  config: SnykApiConfig,
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const { v1 } = getBaseUrl(config);
  const rawUrl = path.startsWith("http") ? path : `${v1}${path.startsWith("/") ? path : `/${path}`}`;
  const url = assertAllowedUrl(config, rawUrl);
  return fetchWithRetry(v1RateLimiter, () =>
    fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `token ${config.token}`,
        ...options.headers,
      },
    })
  );
}

/** GET org settings (V1) */
export async function getOrgSettings(config: SnykApiConfig, orgId: string): Promise<Record<string, unknown>> {
  const safe = sanitizePathSegment(orgId, "org_id");
  const res = await v1Fetch(config, `org/${safe}/settings`);
  if (!res.ok) throw new Error(`V1 getOrgSettings failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** PUT org settings (V1). Only requestAccess is editable in V1. */
export async function updateOrgSettings(
  config: SnykApiConfig,
  orgId: string,
  body: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const safe = sanitizePathSegment(orgId, "org_id");
  const res = await v1Fetch(config, `org/${safe}/settings`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`V1 updateOrgSettings failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/**
 * `listIntegrations` gets looked up 2-3 times in a single `snyk_clone_integration` call (the
 * CLI-integration check, then `formatIntegrationId` in the dry-run text, then again in the
 * apply confirmation) — memoize briefly so those collapse into one request, the same fix
 * `getOrgName` already got in rest.ts. Unlike that cache, this one can mask an integration
 * added to the org within the last minute; accepted here since nothing in this server reads
 * this map for correctness-critical decisions (only for display and the CLI-type check, which
 * fails safe either way — the clone call itself will still reject a CLI integration server-side).
 */
const INTEGRATIONS_TTL_MS = 60_000;
const integrationsCache = new Map<string, { map: Record<string, string>; at: number }>();

/**
 * GET integrations for org (V1). Returns `{ integrationType: integrationId }`.
 * Normalizes two response shapes seen from this endpoint: a flat `{ type: id }` map
 * (the common case, detected by every value being a string), and an `{ integrations: [...] }`
 * array form — both are converted to the same flat map so every caller only deals with one shape.
 */
export async function listIntegrations(config: SnykApiConfig, orgId: string): Promise<Record<string, string>> {
  const safe = sanitizePathSegment(orgId, "org_id");
  const cached = integrationsCache.get(safe);
  if (cached && Date.now() - cached.at < INTEGRATIONS_TTL_MS) return cached.map;

  const res = await v1Fetch(config, `org/${safe}/integrations`);
  if (!res.ok) throw new Error(`V1 listIntegrations failed: ${res.status} ${await res.text()}`);
  const raw = (await res.json()) as Record<string, string> | { integrations?: { id: string; type?: string }[] };
  let result: Record<string, string>;
  if (raw && typeof raw === "object" && !Array.isArray(raw) && raw.integrations == null && Object.keys(raw).some((k) => typeof (raw as Record<string, string>)[k] === "string")) {
    result = raw as Record<string, string>;
  } else if (Array.isArray((raw as { integrations?: unknown }).integrations)) {
    const arr = (raw as { integrations: { id: string; type?: string }[] }).integrations;
    const out: Record<string, string> = {};
    for (const i of arr) {
      const type = i.type ?? i.id;
      out[type] = i.id;
    }
    result = out;
  } else {
    result = raw as Record<string, string>;
  }
  integrationsCache.set(safe, { map: result, at: Date.now() });
  return result;
}

/** Get integration type name for an integration id in an org. Returns null if not found. */
export async function getIntegrationTypeName(config: SnykApiConfig, orgId: string, integrationId: string): Promise<string | null> {
  const map = await listIntegrations(config, orgId);
  for (const [typeName, id] of Object.entries(map)) {
    if (id === integrationId) return typeName;
  }
  return null;
}

/** True if this integration type is the Snyk CLI integration (not supported for clone). */
export function isCliIntegrationType(typeName: string | null): boolean {
  return typeName != null && typeName.trim().toLowerCase() === "cli";
}

/**
 * Clone integration from source org to target org (V1).
 * POST org/{sourceOrgId}/integrations/{integrationId}/clone with body { "target_org_id": "..." }.
 * Docs: Clone an integration (with settings and credentials)
 * CLI integrations are excluded (not clonable via this API).
 */
export async function cloneIntegration(
  config: SnykApiConfig,
  sourceOrgId: string,
  integrationId: string,
  targetOrgId: string
): Promise<Record<string, unknown>> {
  const safeSource = sanitizePathSegment(sourceOrgId, "source_org_id");
  const safeIntegration = sanitizePathSegment(integrationId, "integration_id");
  const safeTarget = sanitizePathSegment(targetOrgId, "target_org_id");
  const typeName = await getIntegrationTypeName(config, safeSource, safeIntegration);
  if (isCliIntegrationType(typeName)) {
    throw new Error("CLI integration cannot be cloned; exclude it when copying integrations between orgs.");
  }
  const res = await v1Fetch(config, `org/${safeSource}/integrations/${safeIntegration}/clone`, {
    method: "POST",
    body: JSON.stringify({ destinationOrgPublicId: safeTarget }),
  });
  if (!res.ok) throw new Error(`V1 cloneIntegration failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}

/** Add tag/label to project (V1). Labels are called "tags" in V1 project API. */
export async function addProjectTag(
  config: SnykApiConfig,
  orgId: string,
  projectId: string,
  key: string,
  value?: string
): Promise<unknown> {
  const safeOrg = sanitizePathSegment(orgId, "org_id");
  const safeProject = sanitizePathSegment(projectId, "project_id");
  const res = await v1Fetch(config, `org/${safeOrg}/project/${safeProject}/tags`, {
    method: "POST",
    body: JSON.stringify(value !== undefined ? { key, value } : { key }),
  });
  if (!res.ok) throw new Error(`V1 addProjectTag failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Remove tag from project (V1). */
export async function removeProjectTag(
  config: SnykApiConfig,
  orgId: string,
  projectId: string,
  key: string
): Promise<unknown> {
  const safeOrg = sanitizePathSegment(orgId, "org_id");
  const safeProject = sanitizePathSegment(projectId, "project_id");
  const res = await v1Fetch(config, `org/${safeOrg}/project/${safeProject}/tags/remove`, {
    method: "POST",
    body: JSON.stringify({ key }),
  });
  if (!res.ok) throw new Error(`V1 removeProjectTag failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Response shape for a successful project move. */
export type MoveProjectResult = { originOrg: string; destinationOrg: string; movedProject: string };

/**
 * Move a project from one org to another (V1). PUT org/{orgId}/project/{projectId}/move,
 * body `{ targetOrgId }`. No REST equivalent exists — checked the REST API's
 * `PatchProjectRequest` schema directly; it only covers project metadata (business
 * criticality, environment, lifecycle, tags), nothing for reassigning a project's org.
 * Per Snyk's docs, moving across group boundaries needs a personal API key, not a service
 * account key, in addition to the usual group-admin permission this whole server assumes.
 */
export async function moveProject(
  config: SnykApiConfig,
  orgId: string,
  projectId: string,
  targetOrgId: string
): Promise<MoveProjectResult> {
  const safeOrg = sanitizePathSegment(orgId, "org_id");
  const safeProject = sanitizePathSegment(projectId, "project_id");
  const safeTarget = sanitizePathSegment(targetOrgId, "target_org_id");
  const res = await v1Fetch(config, `org/${safeOrg}/project/${safeProject}/move`, {
    method: "PUT",
    body: JSON.stringify({ targetOrgId: safeTarget }),
  });
  if (!res.ok) throw new Error(`V1 moveProject failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<MoveProjectResult>;
}

/**
 * Create a new organization (V1).
 * POST /org with body: name, optional group_id, optional source_org_id (to copy settings from a template org).
 * Docs: Create a new organization
 */
export async function createOrganization(
  config: SnykApiConfig,
  params: { name: string; group_id?: string; source_org_id?: string }
): Promise<Record<string, unknown>> {
  const body: Record<string, string> = { name: params.name };
  if (params.group_id) {
    body.groupId = sanitizePathSegment(params.group_id, "group_id");
  }
  if (params.source_org_id) {
    body.sourceOrgId = sanitizePathSegment(params.source_org_id, "source_org_id");
  }
  const res = await v1Fetch(config, "org", {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`V1 createOrganization failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}
