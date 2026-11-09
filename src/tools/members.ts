/**
 * Membership tools (REST, GA): who belongs to an org or group, and with which role. Read-only
 * for now — the API can also add, change, and remove memberships, which would be destructive
 * tools of their own.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import { READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, nextPageHint, pageCursors, pageLimitStep10 } from "./format.js";

const ListMembersArgsSchema = z.object({
  org_id: z.string().optional().describe("Org ID — provide this or group_id, not both"),
  group_id: z.string().optional().describe("Group ID — provide this or org_id, not both. Lists group-level memberships (e.g. Group Admin), not every org's members"),
  email: z.string().optional().describe("Only the member with this email"),
  username: z.string().optional().describe("Only the member with this username"),
  user_id: z.string().optional().describe("Only the member with this user ID"),
  role_name: z.string().optional().describe("Only members with this role, e.g. \"Org Admin\", \"Org Collaborator\", \"Group Admin\", or a custom role's name"),
  sort_by: z.enum(["username", "user_display_name", "email", "login_method", "role"]).optional(),
  sort_order: z.enum(["ASC", "DESC"]).optional(),
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
});

function describeMember(m: rest.MembershipResource): string {
  const u = m.relationships?.user?.data;
  const ua = u?.attributes ?? {};
  const who = [ua.name, ua.email && ua.email !== ua.name ? `<${ua.email}>` : ""].filter(Boolean).join(" ") || ua.username || "(unknown user)";
  const extras = [ua.username && ua.username !== ua.email ? `username ${ua.username}` : "", ua.login_method ? `login ${ua.login_method}` : ""].filter(Boolean).join(", ");
  const role = m.relationships?.role?.data?.attributes?.name ?? "(no role)";
  return `${who} — ${role}; user_id ${u?.id ?? "?"}${extras ? `; ${extras}` : ""}; membership ${m.id}`;
}

export const listMembers = defineTool({
  name: "snyk_list_members",
  description: "List the members of an org or group with their role, one line each: name, email, role, user_id, login method. Filter by email, username, user_id, or role_name (e.g. \"Org Admin\") — for example to answer who has admin access, or whether someone still has access. group_id lists group-level memberships only, not members of each org. user_id is what snyk_update_projects takes as owner_user_id. Read-only.",
  schema: ListMembersArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    if ((a.org_id ? 1 : 0) + (a.group_id ? 1 : 0) !== 1) {
      return { content: [{ type: "text", text: "Provide exactly one of org_id or group_id." }], isError: true };
    }
    const scope = a.org_id ? "orgs" : "groups";
    const id = (a.org_id ?? a.group_id)!;
    const data = await rest.listMemberships(config, scope, id, {
      email: a.email,
      username: a.username,
      user_id: a.user_id,
      role_name: a.role_name,
      sort_by: a.sort_by,
      sort_order: a.sort_order,
      limit: a.limit ?? 100,
      starting_after: a.starting_after,
      ending_before: a.ending_before,
    });
    const members = data.data ?? [];
    const pagination = pageCursors(data.links);
    const where = scope === "orgs" ? `org ${await formatOrgId(config, id)}` : `group ${id}`;
    const filters = [a.email && `email ${a.email}`, a.username && `username ${a.username}`, a.user_id && `user ${a.user_id}`, a.role_name && `role ${a.role_name}`].filter(Boolean);
    const header = `${members.length} member(s) of ${where}${filters.length ? ` matching ${filters.join(", ")}` : ""}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    const body = members.length ? members.map(describeMember).join("\n") : "No members.";
    return { content: [{ type: "text", text: `${header}\n\n${body}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});
