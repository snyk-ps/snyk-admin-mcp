/** Argument checks shared by tools in more than one area. */
import type { ToolResult } from "../mutation.js";

/**
 * An error result when source and target are the same org, else null. Copying settings,
 * moving projects, or cloning an integration onto the org it came from is never intended —
 * it usually means the two IDs got mixed up — so it's rejected before any API call.
 */
export function sameOrgError(sourceOrgId: string, targetOrgId: string): ToolResult | null {
  if (sourceOrgId.trim().toLowerCase() !== targetOrgId.trim().toLowerCase()) return null;
  return {
    content: [{ type: "text", text: `source_org_id and target_org_id are the same org (${sourceOrgId}). Use a different target org.` }],
    isError: true,
  };
}
