/** Audit log search for an org or a group (REST API, GA). Read-only. */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import { READ_ONLY, defineTool } from "./types.js";

// --- Search audit logs (REST, GA). Read-only; exactly one of org_id/group_id. ---
const SearchAuditLogsArgsSchema = z.object({
  org_id: z.string().optional().describe("Organization ID to search (provide this or group_id, not both)"),
  group_id: z.string().optional().describe("Group ID to search (provide this or org_id, not both)"),
  from: z.string().optional().describe("Start of the search window, RFC3339 (e.g. 2024-01-02T16:30:00Z). Defaults to the start of yesterday if omitted."),
  to: z.string().optional().describe("End of the search window (exclusive), RFC3339."),
  events: z.array(z.string()).optional().describe("Only include these event types (e.g. org.settings.edit). Cannot be combined with exclude_events. Note: api.access events are omitted unless explicitly included here."),
  exclude_events: z.array(z.string()).optional().describe("Exclude these event types. Cannot be combined with events."),
  user_id: z.string().optional().describe("Filter to a specific user ID"),
  project_id: z.string().optional().describe("Filter to a specific project ID"),
  size: z.number().int().min(1).max(100).optional().describe("Results per page (1-100, default 100)"),
  sort_order: z.enum(["ASC", "DESC"]).optional().describe("Sort order, default DESC (newest first)"),
  cursor: z.string().optional().describe("Pagination cursor: next_cursor from a previous response. Resend the same filters with it."),
});

export const searchAuditLogs = defineTool({
  name: "snyk_search_audit_logs",
  description: "Search an org's or group's audit logs (exactly one of org_id, group_id) by time range (RFC3339 from/to), user_id, project_id, and event types (events or exclude_events, not both). api.access events are left out unless listed in events. Paged with cursor. Read-only.",
  schema: SearchAuditLogsArgsSchema,
  annotations: READ_ONLY,
  handler: async (parsed, config) => {
    if ((parsed.org_id ? 1 : 0) + (parsed.group_id ? 1 : 0) !== 1) {
      throw new Error("Provide exactly one of org_id or group_id.");
    }
    if (parsed.events && parsed.exclude_events) {
      throw new Error("Provide events or exclude_events, not both.");
    }
    const scope = parsed.org_id ? "orgs" : "groups";
    const scopeId = (parsed.org_id ?? parsed.group_id)!;
    const data = await rest.searchAuditLogs(config, scope, scopeId, {
      from: parsed.from,
      to: parsed.to,
      events: parsed.events,
      exclude_events: parsed.exclude_events,
      user_id: parsed.user_id,
      project_id: parsed.project_id,
      size: parsed.size,
      sort_order: parsed.sort_order,
      cursor: parsed.cursor,
    });
    const items = data.data?.items ?? [];
    const summary = items.length
      ? items.map((i) => `${i.created} — ${i.event}${i.project_id ? ` (project ${i.project_id})` : ""}`).join("\n")
      : "No audit log entries in this window.";
    const nextCursor = rest.cursorFromLink(data.links?.next, "cursor");
    const nextHint = nextCursor
      ? `\n\nMore results: pass cursor="${nextCursor}" with the same filters (org/group, from, to, events, size) to get the next page.`
      : "";
    // `links` is replaced by the bare cursor so the raw next-link path can't be mistaken
    // for the cursor value (the API rejects that with 400 "invalid cursor").
    const { links: _links, ...withoutLinks } = data;
    const full = { ...withoutLinks, pagination: { next_cursor: nextCursor } };
    return {
      content: [{ type: "text", text: `${summary}${nextHint}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});
