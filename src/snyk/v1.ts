import { assertAllowedUrl, getBaseUrl, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, v1RateLimiter } from "./rateLimit.js";

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

/** GET integrations for org (V1). Returns object: integration type name -> integration id. */
export async function listIntegrations(config: SnykApiConfig, orgId: string): Promise<Record<string, string>> {
  const safe = sanitizePathSegment(orgId, "org_id");
  const res = await v1Fetch(config, `org/${safe}/integrations`);
  if (!res.ok) throw new Error(`V1 listIntegrations failed: ${res.status} ${await res.text()}`);
  const raw = (await res.json()) as Record<string, string> | { integrations?: { id: string; type?: string }[] };
  if (raw && typeof raw === "object" && !Array.isArray(raw) && raw.integrations == null && Object.keys(raw).some((k) => typeof (raw as Record<string, string>)[k] === "string")) {
    return raw as Record<string, string>;
  }
  if (Array.isArray((raw as { integrations?: unknown }).integrations)) {
    const arr = (raw as { integrations: { id: string; type?: string }[] }).integrations;
    const out: Record<string, string> = {};
    for (const i of arr) {
      const type = i.type ?? i.id;
      out[type] = i.id;
    }
    return out;
  }
  return raw as Record<string, string>;
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
