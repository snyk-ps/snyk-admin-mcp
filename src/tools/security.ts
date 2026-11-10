/**
 * Read-only security checks: who has API access (service accounts), which Snyk Apps are
 * installed, and which Broker connections an org uses. REST, GA.
 *
 * Service accounts are the sensitive one: the API can return an account's API key, access
 * token, or client secret. rest.listServiceAccounts keeps only an allow-list of fields, and
 * this tool prints only those, so no credential ever reaches the AI.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import * as v1 from "../snyk/v1.js";
import type { SnykApiConfig } from "../snyk/types.js";
import { READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, nextPageHint, pageCursors, pageLimitStep10 } from "./format.js";

const ScopeFields = {
  org_id: z.string().optional().describe("Org ID — provide this or group_id, not both"),
  group_id: z.string().optional().describe("Group ID — provide this or org_id, not both"),
};

function scopeOf(a: { org_id?: string; group_id?: string }): { scope: "orgs" | "groups"; id: string } | null {
  if ((a.org_id ? 1 : 0) + (a.group_id ? 1 : 0) !== 1) return null;
  return a.org_id ? { scope: "orgs", id: a.org_id } : { scope: "groups", id: a.group_id! };
}
const scopeError = { content: [{ type: "text" as const, text: "Provide exactly one of org_id or group_id." }], isError: true };

async function describeScope(config: SnykApiConfig, s: { scope: "orgs" | "groups"; id: string }): Promise<string> {
  return s.scope === "orgs" ? `org ${await formatOrgId(config, s.id)}` : `group ${s.id}`;
}

// --- Service accounts ---

/**
 * A readable label for a service account's `auth_type` value. (A switch rather than a lookup
 * object: an object whose keys are named like credentials, e.g. `api_key: "..."`, reads to
 * secret scanners as a hardcoded secret, though these are only type names and labels.)
 */
function authTypeLabel(authType: string | undefined): string {
  switch (authType) {
    case "api_key": return "API key (long-lived, no expiry)";
    case "oauth_client_secret": return "OAuth client secret";
    case "oauth_private_key_jwt": return "OAuth private key JWT";
    case "access_token": return "access token";
    default: return authType ?? "?";
  }
}

const ListServiceAccountsArgsSchema = z.object({
  ...ScopeFields,
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

export const listServiceAccounts = defineTool({
  name: "snyk_list_service_accounts",
  description: "List an org's or group's service accounts (non-human API access), one line each: name, ID, how it authenticates (a long-lived API key or OAuth, with token lifetime), level, role, and when it was created. Use it to review who has API access and spot long-lived API keys. Never returns keys, tokens, or secrets. Read-only.",
  schema: ListServiceAccountsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const s = scopeOf(a);
    if (!s) return scopeError;
    const data = await rest.listServiceAccounts(config, s.scope, s.id, { limit: a.limit ?? 100, starting_after: a.starting_after });
    // Role names come from the group's role list; if that can't be read, roles show as IDs.
    const groupId = s.scope === "groups" ? s.id : await rest.getOrgGroupId(config, s.id);
    const roles = groupId ? await v1.listGroupRoles(config, groupId).catch(() => []) : [];
    const roleName = new Map(roles.map((r) => [r.publicId, r.name]));
    const accounts = data.data;
    // That list only has org roles. Group roles (e.g. Group Admin) are named in the group's
    // memberships, so look there for any role still unnamed.
    if (groupId && accounts.some((sa) => sa.attributes.role_id && !roleName.has(sa.attributes.role_id))) {
      const members = await rest.listMemberships(config, "groups", groupId, { limit: 100 }).catch(() => ({ data: [] as rest.MembershipResource[] }));
      for (const m of members.data ?? []) {
        const role = m.relationships?.role?.data;
        if (role?.id && role.attributes?.name && !roleName.has(role.id)) roleName.set(role.id, role.attributes.name);
      }
    }
    const lines = accounts.map((sa) => {
      const at = sa.attributes;
      const auth = authTypeLabel(at.auth_type);
      const ttl = at.access_token_ttl_seconds ? `, token lifetime ${at.access_token_ttl_seconds}s` : "";
      const expires = at.access_token_expires_at ? `, token expires ${at.access_token_expires_at}` : "";
      const role = at.role_id ? roleName.get(at.role_id) ?? `role ${at.role_id}` : "no role";
      return `${at.name ?? "(no name)"} (${sa.id}) — ${auth}${ttl}${expires}; ${at.level ?? "?"} level; ${role}${at.created_at ? `; created ${at.created_at.slice(0, 10)}` : ""}`;
    });
    const pagination = pageCursors(data.links);
    const apiKeys = accounts.filter((sa) => sa.attributes.auth_type === "api_key").length;
    const keyNote = apiKeys ? `\n\n${apiKeys} of these use a long-lived API key, which doesn't expire; OAuth accounts get short-lived tokens.` : "";
    const where = await describeScope(config, s);
    const header = `${accounts.length} service account(s) in ${where}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    return { content: [{ type: "text", text: `${header}\n\n${lines.join("\n") || "No service accounts."}${keyNote}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});

// --- Installed Snyk Apps ---

const ListAppInstallsArgsSchema = z.object({
  ...ScopeFields,
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

export const listAppInstalls = defineTool({
  name: "snyk_list_app_installs",
  description: "List the Snyk Apps installed in an org or group (third-party and Snyk integrations that act through Snyk Apps, e.g. Jira or Bitbucket Cloud), one line each: app name, install ID, app client ID, and install date. Use it to review which apps have access. Read-only.",
  schema: ListAppInstallsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const s = scopeOf(a);
    if (!s) return scopeError;
    const data = await rest.listAppInstalls(config, s.scope, s.id, { limit: a.limit ?? 100, starting_after: a.starting_after });
    const installs = data.data ?? [];
    const lines = installs.map((i) => {
      const app = i.relationships?.app?.data;
      return `${app?.attributes?.name ?? "(unknown app)"} — install ${i.id}; app ${app?.id ?? "?"}${app?.attributes?.client_id ? `, client ${app.attributes.client_id}` : ""}${i.attributes?.installed_at ? `; installed ${i.attributes.installed_at.slice(0, 10)}` : ""}`;
    });
    const pagination = pageCursors(data.links);
    const where = await describeScope(config, s);
    const header = `${installs.length} app install(s) in ${where}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    return { content: [{ type: "text", text: `${header}\n\n${lines.join("\n") || "No apps installed."}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});

// --- Broker connections ---

const ListBrokerConnectionsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  limit: z.number().int().min(1).max(100).optional().describe("Results per page, 1-100 (default 100 here)"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

export const listBrokerConnections = defineTool({
  name: "snyk_list_broker_connections",
  description: "List the Snyk Broker connections an org uses (how Snyk reaches private SCMs, registries, or Jira through a Broker), one line each: name, connection type, deployment ID, and connection ID. Read-only.",
  schema: ListBrokerConnectionsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const data = await rest.listBrokerConnections(config, a.org_id, { limit: a.limit ?? 100, starting_after: a.starting_after });
    const conns = data.data ?? [];
    const lines = conns.map((c) => `${c.attributes?.name ?? "(no name)"} (${c.id}) — ${c.attributes?.connection_type ?? "?"}; deployment ${c.attributes?.deployment_id ?? "?"}`);
    const pagination = pageCursors(data.links);
    const where = await formatOrgId(config, a.org_id);
    const header = `${conns.length} Broker connection(s) in ${where}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    return { content: [{ type: "text", text: `${header}\n\n${lines.join("\n") || "No Broker connections."}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});
