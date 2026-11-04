/** Display helpers shared by several tool areas. */
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
