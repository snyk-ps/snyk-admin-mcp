/** Display helpers and argument schemas shared by several tool areas. */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import * as v1 from "../snyk/v1.js";
import type { SnykApiConfig } from "../snyk/types.js";

/** Format org_id as "name (id)" when name is available. */
export async function formatOrgId(config: SnykApiConfig, orgId: string): Promise<string> {
  const name = await rest.getOrgName(config, orgId);
  return name ? `${name} (${orgId})` : orgId;
}

/** Format integration_id as "type (id)" when type is available. */
export async function formatIntegrationId(config: SnykApiConfig, orgId: string, integrationId: string): Promise<string> {
  const typeName = await v1.getIntegrationTypeName(config, orgId, integrationId);
  return typeName ? `${typeName} (${integrationId})` : integrationId;
}

/** Format a list response's cursor links as bare cursors the caller can pass straight back. */
export function pageCursors(links: rest.PageLinks | undefined) {
  return {
    next_starting_after: rest.cursorFromLink(links?.next, "starting_after"),
    prev_ending_before: rest.cursorFromLink(links?.prev, "ending_before"),
  };
}

/** The "pass this cursor for the next page" line every paged tool ends with. */
export function nextPageHint(next: string | null | undefined): string {
  return next ? `\n\nMore results: pass starting_after="${next}" (with the same filters) to get the next page.` : "";
}

/**
 * Page size for the REST endpoints whose spec says `minimum: 10, maximum: 100, multipleOf: 10`
 * (orgs, projects, memberships, collections). Anything else is a 400 from the API, so it's
 * rejected here with a clear message instead. The Asset and Inventory endpoints take any
 * 10-100, and use their own schema.
 */
export function pageLimitStep10(defaultNote = "API default 10") {
  return z.number().int().min(10).max(100).multipleOf(10).optional().describe(`Results per page: 10-100, in steps of 10 (${defaultNote})`);
}

/** "C1 H2 M0 L4" from a {critical, high, medium, low} count object; "" when absent. */
export function issueCountsText(c: { critical?: number; high?: number; medium?: number; low?: number } | undefined | null): string {
  if (!c) return "";
  return `C${c.critical ?? 0} H${c.high ?? 0} M${c.medium ?? 0} L${c.low ?? 0}`;
}

/** One line per project: name, ID, type/origin/branch, then classification and tags when set. */
export function describeProject(p: rest.ProjectResource): string {
  const a = p.attributes ?? {};
  const where = [a.type, a.origin, a.target_reference ? `ref ${a.target_reference}` : "", a.status && a.status !== "active" ? a.status : ""].filter(Boolean).join(", ");
  const parts: string[] = [];
  if (a.business_criticality?.length) parts.push(`criticality ${a.business_criticality.join("/")}`);
  if (a.environment?.length) parts.push(`env ${a.environment.join("/")}`);
  if (a.lifecycle?.length) parts.push(`lifecycle ${a.lifecycle.join("/")}`);
  if (a.tags?.length) parts.push(`tags ${a.tags.map((t) => `${t.key}:${t.value}`).join(", ")}`);
  const issues = issueCountsText(p.meta?.latest_issue_counts);
  if (issues) parts.push(`issues ${issues}`);
  return `${a.name ?? "(no name)"} (${p.id})${where ? ` — ${where}` : ""}${parts.length ? `; ${parts.join("; ")}` : ""}`;
}

/**
 * Throw if any project ID isn't in the org, naming the missing ones. Used by the project dry
 * runs, so a typo or a project from another org is caught before an approval token is issued
 * rather than failing part-way through an apply. Returns the projects found, keyed by lowercase ID.
 */
export async function requireProjectsInOrg(config: SnykApiConfig, orgId: string, projectIds: string[]): Promise<Map<string, rest.ProjectResource>> {
  const { found, missing } = await rest.findProjectsByIds(config, orgId, projectIds);
  if (missing.length) {
    const where = await formatOrgId(config, orgId);
    throw new Error(`${missing.length} project ID(s) not found in ${where}: ${missing.join(", ")}. Use snyk_list_projects to find this org's project IDs. Nothing was planned.`);
  }
  return found;
}
