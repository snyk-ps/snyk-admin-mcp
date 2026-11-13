/**
 * Access tools (REST, GA): who belongs to an org or group and with which role, everywhere one
 * person has access in a group, and invites that haven't been accepted. All read-only, on
 * purpose: the API can also add, change, and remove memberships and send or revoke invites, but
 * this server doesn't wrap those, so it can review access without being able to change it.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import type { SnykApiConfig } from "../snyk/types.js";
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

const errorResult = (text: string) => ({ content: [{ type: "text" as const, text }], isError: true });

// --- One person's access across a group ---

/** How many of a group's orgs an email lookup reads (100 per page) before asking for a user_id. */
const EMAIL_LOOKUP_MAX_ORGS = 500;

/**
 * Find a user's ID from their email: first in the group's own memberships, then in its orgs',
 * a page of 100 orgs at a time. Snyk's `email` filter is an exact match that ignores case
 * (live-checked), and the result is compared the same way.
 */
async function findUserIdByEmail(config: SnykApiConfig, groupId: string, email: string): Promise<{ user_id: string } | { error: string }> {
  const want = email.trim().toLowerCase();
  const idOf = (members: rest.MembershipResource[] | undefined) =>
    members?.find((m) => m.relationships?.user?.data?.attributes?.email?.toLowerCase() === want)?.relationships?.user?.data?.id;
  const inGroup = idOf((await rest.listMemberships(config, "groups", groupId, { email: want, limit: 10 })).data);
  if (inGroup) return { user_id: inGroup };
  let cursor: string | undefined;
  let scanned = 0;
  while (scanned < EMAIL_LOOKUP_MAX_ORGS) {
    const page = await rest.listOrgs(config, { group_id: groupId, limit: 100, starting_after: cursor });
    const orgs = page.data ?? [];
    scanned += orgs.length;
    // An org whose members the token can't read just doesn't match.
    const ids = await Promise.all(orgs.map((o) => rest.listMemberships(config, "orgs", o.id, { email: want, limit: 10 }).then((r) => idOf(r.data), () => undefined)));
    const found = ids.find(Boolean);
    if (found) return { user_id: found };
    const next = rest.cursorFromLink(page.links?.next, "starting_after");
    if (!next || orgs.length === 0) return { error: `No member with email ${email} in group ${groupId} or any of its ${scanned} org(s).` };
    cursor = next;
  }
  return { error: `No member with email ${email} in group ${groupId}'s memberships or its first ${scanned} orgs. Pass user_id instead: snyk_list_members with email on an org they belong to shows it.` };
}

const ListUserAccessArgsSchema = z.object({
  group_id: z.string().describe("Group ID (snyk_list_orgs shows each org's group_id)"),
  user_id: z.string().optional().describe("The person's user ID — provide this or email"),
  email: z.string().optional().describe(`The person's email — provide this or user_id. Exact match, ignoring case; looked up in the group's memberships, then its orgs' (up to ${EMAIL_LOOKUP_MAX_ORGS} orgs)`),
  org_name: z.string().optional().describe("Only orgs whose name contains this, ignoring case"),
  role_name: z.string().optional().describe("Only org memberships with this role, e.g. \"Org Admin\" (ignoring case)"),
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

export const listUserAccess = defineTool({
  name: "snyk_list_user_access",
  description: "Show everywhere one person has access in a group: their group-level role (e.g. Group Admin) and every org they're a member of, one line per org with their role and the date they were added. Look them up by user_id or email; filter by org name or role. Use it to review someone's access, or to see what to remove when someone leaves. Read-only: this server can't change memberships.",
  schema: ListUserAccessArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    if ((a.user_id ? 1 : 0) + (a.email ? 1 : 0) !== 1) return errorResult("Provide exactly one of user_id or email.");
    let userId = a.user_id;
    if (!userId) {
      const found = await findUserIdByEmail(config, a.group_id, a.email!);
      if ("error" in found) return errorResult(found.error);
      userId = found.user_id;
    }
    const [groupMemberships, page] = await Promise.all([
      // Only for the group-level role line; if it can't be read, that line says so.
      rest.listMemberships(config, "groups", a.group_id, { user_id: userId, limit: 10 }).then((r) => r.data ?? [], () => null),
      rest.listGroupUserOrgMemberships(config, a.group_id, userId, {
        org_name: a.org_name,
        role_name: a.role_name,
        limit: a.limit ?? 100,
        starting_after: a.starting_after,
      }),
    ]);
    const memberships = page.data ?? [];
    // The API gives each org's slug, not its name, so names come from the org itself.
    const names = await Promise.all(memberships.map((m) => (m.relationships?.org?.data?.id ? rest.getOrgName(config, m.relationships.org.data.id).catch(() => null) : null)));
    const lines = memberships.map((m, i) => {
      const org = m.relationships?.org?.data;
      const role = m.relationships?.role?.data?.attributes?.name ?? "(no role)";
      const added = m.attributes?.created_at ? `; added ${m.attributes.created_at.slice(0, 10)}` : "";
      return `${names[i] ?? org?.attributes?.name ?? "(unknown org)"} (${org?.id ?? "?"}) — ${role}${added}; membership ${m.id}`;
    });

    const ua = groupMemberships?.[0]?.relationships?.user?.data?.attributes ?? memberships[0]?.relationships?.user?.data?.attributes;
    const who = ua ? [ua.name, ua.email && ua.email !== ua.name ? `<${ua.email}>` : ""].filter(Boolean).join(" ") || ua.username : a.email;
    const groupRoles = groupMemberships?.map((m) => m.relationships?.role?.data?.attributes?.name ?? "(no role)") ?? null;
    const groupLine = groupRoles === null
      ? "Group role: unknown (couldn't read the group's memberships)"
      : groupRoles.length
        ? `Group role: ${groupRoles.join(", ")}${groupRoles.some((r) => r.toLowerCase() === "group admin") ? ". A Group Admin can reach every org in the group, not only the ones below" : ""}`
        : "Group role: none";
    const total = page.meta?.org_membership_count;
    const pagination = pageCursors(page.links);
    const filters = [a.org_name && `org name "${a.org_name}"`, a.role_name && `role "${a.role_name}"`].filter(Boolean);
    const countText = `${memberships.length}${typeof total === "number" && total !== memberships.length ? ` of ${total}` : ""} org membership(s)`;
    const header = `Access for ${who ? `${who} ` : ""}(user_id ${userId}) in group ${a.group_id}:\n${groupLine}.\n\n${countText}${filters.length ? ` matching ${filters.join(", ")}` : ""}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    return { content: [{ type: "text", text: `${header}\n${lines.join("\n") || "No org memberships."}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});

// --- Pending invites ---

const ListInvitesArgsSchema = z.object({
  org_ids: z.array(z.string().min(1)).min(1).max(25).optional().describe("Org IDs to check (up to 25) — provide this or group_id"),
  group_id: z.string().optional().describe("Check this group's orgs, 100 per call — provide this or org_ids"),
  starting_after: z.string().optional().describe("With group_id: from next_starting_after, for the group's next 100 orgs"),
});

export const listInvites = defineTool({
  name: "snyk_list_invites",
  description: "List invites to orgs that haven't been accepted, one line each: email, the role they'll get, and the org. Check up to 25 orgs by ID, or a group's orgs 100 at a time. Use it to find stale or unexpected invites. Read-only: this server can't send or revoke invites.",
  schema: ListInvitesArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    if ((a.org_ids ? 1 : 0) + (a.group_id ? 1 : 0) !== 1) return errorResult("Provide exactly one of org_ids or group_id.");
    if (a.starting_after && !a.group_id) return errorResult("starting_after only applies with group_id.");
    let orgs: { id: string; name: string | null }[];
    let nextOrgs: string | null = null;
    if (a.group_id) {
      const page = await rest.listOrgs(config, { group_id: a.group_id, limit: 100, starting_after: a.starting_after });
      orgs = (page.data ?? []).map((o) => ({ id: o.id, name: o.attributes?.name ?? null }));
      nextOrgs = rest.cursorFromLink(page.links?.next, "starting_after");
    } else {
      const ids = [...new Set(a.org_ids!.map((id) => id.toLowerCase()))];
      orgs = await Promise.all(ids.map(async (id) => ({ id, name: await rest.getOrgName(config, id).catch(() => null) })));
    }
    const results = await Promise.all(orgs.map((org) =>
      rest.listAllOrgInvites(config, org.id).then(
        (r) => ({ org, ...r, error: undefined }),
        (err: unknown) => ({ org, invites: [] as rest.OrgInvite[], truncated: false, error: err instanceof Error ? err.message : String(err) })
      )
    ));
    const label = (o: { id: string; name: string | null }) => (o.name ? `${o.name} (${o.id})` : o.id);
    const lines: string[] = [];
    let pending = 0;
    for (const r of results) {
      for (const inv of r.invites) {
        // Snyk lists pending invites; one that's no longer active (accepted or revoked) is marked.
        const active = inv.attributes?.is_active !== false;
        if (active) pending++;
        lines.push(`${inv.attributes?.email ?? "(no email)"} — ${inv.attributes?.role ?? "(no role)"}; ${label(r.org)}; invite ${inv.id}${active ? "" : "; no longer active (accepted or revoked)"}`);
      }
    }
    const withInvites = results.filter((r) => r.invites.length).length;
    const failed = results.filter((r) => r.error);
    const truncated = results.filter((r) => r.truncated);
    const scope = a.group_id ? ` in group ${a.group_id}${nextOrgs ? " (the group has more orgs; see below)" : ""}` : "";
    const header = `${pending} pending invite(s) in ${withInvites} of ${orgs.length} org(s) checked${scope}:`;
    const failedText = failed.length ? `\n\nCouldn't read invites in ${failed.length} org(s):\n${failed.map((r) => `${label(r.org)}: ${r.error!.slice(0, 200)}`).join("\n")}` : "";
    const truncatedText = truncated.length ? `\n\nOnly the first 1000 invites were read in: ${truncated.map((r) => label(r.org)).join(", ")}.` : "";
    const nextText = nextOrgs ? `\n\nMore orgs: pass starting_after="${nextOrgs}" with the same group_id to check the group's next 100 orgs.` : "";
    return { content: [{ type: "text", text: `${header}\n\n${lines.join("\n") || "No pending invites."}${failedText}${truncatedText}${nextText}` }], isError: false };
  },
});
