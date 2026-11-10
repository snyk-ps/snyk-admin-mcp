/**
 * Project tools: add/remove project tags and move projects between orgs (V1 API), and
 * update project attributes and owner (REST API).
 *
 * Every dry run here looks the project IDs up in the org first (one request per 100 IDs), so a
 * typo or a project from another org fails the dry run instead of the apply — before this, the
 * dry runs echoed whatever IDs they were given and handed out a token.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import * as v1 from "../snyk/v1.js";
import { sanitizePathSegment } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { ADDITIVE, DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, requireProjectsInOrg } from "./format.js";
import { sameOrgError } from "./guards.js";

const ProjectIdsSchema = z.array(z.string().min(1)).min(1).max(1000);

/** Dry-run lines are capped so a large plan stays readable; the full ID list is in the plan JSON. */
const MAX_PLAN_LINES = 25;
function capped(lines: string[]): string {
  const more = lines.length > MAX_PLAN_LINES ? `\n- …and ${lines.length - MAX_PLAN_LINES} more` : "";
  return lines.slice(0, MAX_PLAN_LINES).join("\n") + more;
}

const nameOf = (p: rest.ProjectResource | undefined, id: string) => `${p?.attributes?.name ?? "(no name)"} (${id})`;

// --- Add project tags (V1 project tags). Not a real batch API — one HTTP call per project x tag. ---
const AddProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: ProjectIdsSchema.describe("Project IDs to tag (from snyk_list_projects)"),
  tags: z.array(z.object({
    key: z.string().min(1),
    value: z.string().optional(),
  })).min(1).describe("Tags to add (key or key:value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Remove project tags (V1 project tags). Not a real batch API — one HTTP call per project x key. ---
const RemoveProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: ProjectIdsSchema.describe("Project IDs to remove tags from (from snyk_list_projects)"),
  tag_keys: z.array(z.string().min(1)).min(1).describe("Tag keys to remove (removal is by key only, no value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Move projects between orgs (V1). No REST equivalent, no batch endpoint — one HTTP call per project. ---
const MoveProjectsArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID the projects currently belong to"),
  target_org_id: z.string().describe("Organization ID to move the projects into"),
  project_ids: ProjectIdsSchema.describe("Project IDs to move (from snyk_list_projects on the source org)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

export const addProjectTags = defineTool({
  name: "snyk_add_project_tags",
  description: "Add tags to multiple projects (one V1 API call per project x tag, not a single batch request). Uses Snyk V1 API (project tags). Note: these are project tags, not asset labels — use snyk_update_assets for asset labels. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
  schema: AddProjectTagsArgsSchema,
  annotations: ADDITIVE,
  handler: async (parsed, config) => {
    type AddProjectTagsPlan = { org_id: string; project_ids: string[]; tags: { key: string; value?: string }[]; projects: { id: string; name: string; already: string[] }[] };
    return await runMutationTool<AddProjectTagsPlan>({
      action: "add_project_tags",
      toolName: "snyk_add_project_tags",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags },
      buildPlanData: async () => {
        const found = await requireProjectsInOrg(config, parsed.org_id, parsed.project_ids);
        const projects = parsed.project_ids.map((id) => {
          const current = found.get(id.toLowerCase())?.attributes?.tags ?? [];
          const already = parsed.tags.filter((t) => current.some((c) => c.key === t.key && (t.value === undefined || c.value === t.value))).map((t) => (t.value === undefined ? t.key : `${t.key}:${t.value}`));
          return { id, name: found.get(id.toLowerCase())?.attributes?.name ?? "(no name)", already };
        });
        return { org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags, projects };
      },
      describeDryRun: async (data) => {
        const totalOperations = data.project_ids.length * data.tags.length;
        const where = await formatOrgId(config, data.org_id);
        const tagList = data.tags.map((t) => (t.value === undefined ? t.key : `${t.key}:${t.value}`)).join(", ");
        const lines = data.projects.map((p) => `- ${p.name} (${p.id})${p.already.length ? ` — already has ${p.already.join(", ")}` : ""}`);
        return `Dry run – will add ${tagList} to ${data.project_ids.length} project(s) in ${where} (${totalOperations} V1 calls).\n\n${capped(lines)}\n\nPlan:\n${JSON.stringify({ org_id: data.org_id, project_ids: data.project_ids, tags: data.tags }, null, 2)}`;
      },
      apply: async (data) => {
        const safeOrgId = sanitizePathSegment(data.org_id, "org_id");
        const operations = data.project_ids.flatMap((projectId) => data.tags.map((tag) => ({ projectId, tag })));
        const results = await Promise.all(
          operations.map(async ({ projectId, tag }) => {
            try {
              await v1.addProjectTag(config, safeOrgId, sanitizePathSegment(projectId, "project_id"), tag.key, tag.value);
              return { projectId, tag, ok: true as const };
            } catch (err) {
              return { projectId, tag, ok: false as const, error: err instanceof Error ? err.message : String(err) };
            }
          })
        );
        const failed = results.filter((r) => !r.ok).length;
        const summary = failed === 0 ? `Added tags: all ${results.length} operation(s) succeeded.` : `Added tags: ${results.length - failed} of ${results.length} operation(s) succeeded; ${failed} failed.`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});

export const removeProjectTags = defineTool({
  name: "snyk_remove_project_tags",
  description: "Remove tags (by key) from multiple projects (one V1 API call per project x key, not a single batch request). Uses Snyk V1 API (project tags). Removal is by key only — no value needed. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
  schema: RemoveProjectTagsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    type RemoveProjectTagsPlan = { org_id: string; project_ids: string[]; tag_keys: string[]; projects: { id: string; name: string; has: string[] }[] };
    return await runMutationTool<RemoveProjectTagsPlan>({
      action: "remove_project_tags",
      toolName: "snyk_remove_project_tags",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys },
      buildPlanData: async () => {
        const found = await requireProjectsInOrg(config, parsed.org_id, parsed.project_ids);
        const projects = parsed.project_ids.map((id) => {
          const current = found.get(id.toLowerCase())?.attributes?.tags ?? [];
          const has = current.filter((c) => parsed.tag_keys.includes(c.key)).map((c) => `${c.key}:${c.value}`);
          return { id, name: found.get(id.toLowerCase())?.attributes?.name ?? "(no name)", has };
        });
        return { org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys, projects };
      },
      describeDryRun: async (data) => {
        const totalOperations = data.project_ids.length * data.tag_keys.length;
        const where = await formatOrgId(config, data.org_id);
        // Projects that actually lose a tag come first, so they can't be pushed out of the capped list.
        const withKeys = data.projects.filter((p) => p.has.length > 0);
        const without = data.projects.filter((p) => p.has.length === 0);
        const lines = withKeys.map((p) => `- ${p.name} (${p.id}): removes ${p.has.join(", ")}`);
        const note = without.length
          ? `\n\n${without.length} project(s) have none of these keys; removing from them changes nothing: ${without.slice(0, 10).map((p) => p.name).join(", ")}${without.length > 10 ? `, …and ${without.length - 10} more` : ""}`
          : "";
        return `Dry run – will remove tag key(s) ${data.tag_keys.join(", ")} from ${data.project_ids.length} project(s) in ${where} (${totalOperations} V1 calls).${lines.length ? `\n\n${capped(lines)}` : ""}${note}\n\nPlan:\n${JSON.stringify({ org_id: data.org_id, project_ids: data.project_ids, tag_keys: data.tag_keys }, null, 2)}`;
      },
      apply: async (data) => {
        const safeOrgId = sanitizePathSegment(data.org_id, "org_id");
        const operations = data.project_ids.flatMap((projectId) => data.tag_keys.map((key) => ({ projectId, key })));
        const results = await Promise.all(
          operations.map(async ({ projectId, key }) => {
            try {
              await v1.removeProjectTag(config, safeOrgId, sanitizePathSegment(projectId, "project_id"), key);
              return { projectId, key, ok: true as const };
            } catch (err) {
              return { projectId, key, ok: false as const, error: err instanceof Error ? err.message : String(err) };
            }
          })
        );
        const failed = results.filter((r) => !r.ok).length;
        const summary = failed === 0 ? `Removed tags: all ${results.length} operation(s) succeeded.` : `Removed tags: ${results.length - failed} of ${results.length} operation(s) succeeded; ${failed} failed.`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});

export const moveProjects = defineTool({
  name: "snyk_move_projects",
  description: "Move one or more projects from a source org to a target org. Uses Snyk V1 API (no REST equivalent exists). One API call per project — no batch endpoint. Requires group-admin permissions; moving across group boundaries needs a personal API key rather than a service account key. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: MoveProjectsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const sameOrg = sameOrgError(parsed.source_org_id, parsed.target_org_id);
    if (sameOrg) return sameOrg;
    type MoveProjectsPlan = { source_org_id: string; target_org_id: string; project_ids: string[]; names: string[] };
    return await runMutationTool<MoveProjectsPlan>({
      action: "move_projects",
      toolName: "snyk_move_projects",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id, project_ids: parsed.project_ids },
      buildPlanData: async () => {
        const found = await requireProjectsInOrg(config, parsed.source_org_id, parsed.project_ids);
        return {
          source_org_id: parsed.source_org_id,
          target_org_id: parsed.target_org_id,
          project_ids: parsed.project_ids,
          names: parsed.project_ids.map((id) => nameOf(found.get(id.toLowerCase()), id)),
        };
      },
      describeDryRun: async (data) => {
        const sourceLabel = await formatOrgId(config, data.source_org_id);
        const targetLabel = await formatOrgId(config, data.target_org_id);
        return `Dry run – will move ${data.project_ids.length} project(s) from ${sourceLabel} to ${targetLabel} (one V1 API call per project; not atomic — a partial failure leaves some projects moved and some not). Requires group-admin permissions; moving across group boundaries needs a personal API key.\n\n${capped(data.names.map((n) => `- ${n}`))}\n\nPlan:\n${JSON.stringify({ source_org_id: data.source_org_id, target_org_id: data.target_org_id, project_ids: data.project_ids }, null, 2)}`;
      },
      apply: async (data) => {
        const safeSourceOrgId = sanitizePathSegment(data.source_org_id, "source_org_id");
        const results = await Promise.all(
          data.project_ids.map(async (projectId) => {
            try {
              const result = await v1.moveProject(config, safeSourceOrgId, projectId, data.target_org_id);
              return { projectId, ok: true as const, result };
            } catch (err) {
              return { projectId, ok: false as const, error: err instanceof Error ? err.message : String(err) };
            }
          })
        );
        const succeeded = results.filter((r) => r.ok).length;
        const failed = results.length - succeeded;
        const targetLabel = await formatOrgId(config, data.target_org_id);
        const summary = failed === 0
          ? `Moved all ${succeeded} project(s) to ${targetLabel}.`
          : `Moved ${succeeded} of ${results.length} project(s) to ${targetLabel}; ${failed} failed — those remain in the source org.`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});

// --- Update project attributes and owner (REST, GA). One PATCH per project — no batch endpoint. ---
const UpdateProjectsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string().min(1)).min(1).max(500).describe("Project IDs to update (from snyk_list_projects)"),
  business_criticality: z.array(z.enum(rest.PROJECT_BUSINESS_CRITICALITY)).optional().describe("Replaces the current list; [] clears it"),
  environment: z.array(z.enum(rest.PROJECT_ENVIRONMENT)).optional().describe("Replaces the current list; [] clears it"),
  lifecycle: z.array(z.enum(rest.PROJECT_LIFECYCLE)).optional().describe("Replaces the current list; [] clears it"),
  test_frequency: z.enum(rest.PROJECT_TEST_FREQUENCY).optional().describe("How often Snyk retests the project (also when automated fix PRs can open)"),
  owner_user_id: z.guid().nullable().optional().describe("User ID to set as owner (user_id from snyk_list_members), or null to clear the owner"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

type ProjectState = { business_criticality: string[]; environment: string[]; lifecycle: string[]; test_frequency: string | null; owner_user_id: string | null };

function stateOf(p: rest.ProjectResource | undefined): ProjectState {
  const a = p?.attributes ?? {};
  return {
    business_criticality: a.business_criticality ?? [],
    environment: a.environment ?? [],
    lifecycle: a.lifecycle ?? [],
    test_frequency: a.settings?.recurring_tests?.frequency ?? null,
    owner_user_id: p?.relationships?.owner?.data?.id ?? null,
  };
}

const sameList = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join() === [...b].sort().join();

/** The fields of `update` that would change `current`, as "field: old → new" strings. */
function changesFor(current: ProjectState, update: rest.ProjectUpdate): string[] {
  const out: string[] = [];
  const list = (v: string[]) => (v.length ? v.join("/") : "(none)");
  for (const key of ["business_criticality", "environment", "lifecycle"] as const) {
    const next = update[key];
    if (next !== undefined && !sameList(current[key], next)) out.push(`${key} ${list(current[key])} → ${list(next)}`);
  }
  if (update.test_frequency !== undefined && update.test_frequency !== current.test_frequency) out.push(`test_frequency ${current.test_frequency ?? "?"} → ${update.test_frequency}`);
  if (update.owner_user_id !== undefined && (update.owner_user_id ?? null)?.toLowerCase() !== current.owner_user_id?.toLowerCase()) {
    out.push(`owner ${current.owner_user_id ?? "(none)"} → ${update.owner_user_id ?? "(none)"}`);
  }
  return out;
}

export const updateProjects = defineTool({
  name: "snyk_update_projects",
  description: "Set business criticality, environment, lifecycle, test frequency, and/or owner on one or more projects in an org (REST API; one PATCH per project). Each attribute list you pass replaces the project's current list ([] clears it); attributes you leave out are kept. For project tags use snyk_add_project_tags / snyk_remove_project_tags. The dry run checks every project ID and shows each project's current → new values; projects that wouldn't change are skipped. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: UpdateProjectsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const update: rest.ProjectUpdate = {};
    if (parsed.business_criticality !== undefined) update.business_criticality = [...new Set(parsed.business_criticality)];
    if (parsed.environment !== undefined) update.environment = [...new Set(parsed.environment)];
    if (parsed.lifecycle !== undefined) update.lifecycle = [...new Set(parsed.lifecycle)];
    if (parsed.test_frequency !== undefined) update.test_frequency = parsed.test_frequency;
    if (parsed.owner_user_id !== undefined) update.owner_user_id = parsed.owner_user_id;
    if (Object.keys(update).length === 0) {
      return { content: [{ type: "text", text: "Provide at least one of: business_criticality, environment, lifecycle, test_frequency, or owner_user_id." }], isError: true };
    }
    const projectIds = [...new Set(parsed.project_ids.map((id) => id.toLowerCase()))];
    type UpdateProjectsPlan = { org_id: string; update: rest.ProjectUpdate; changes: { id: string; name: string; changes: string[] }[] };
    return await runMutationTool<UpdateProjectsPlan>({
      action: "update_projects",
      toolName: "snyk_update_projects",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, project_ids: projectIds, update },
      buildPlanData: async () => {
        const found = await requireProjectsInOrg(config, parsed.org_id, projectIds);
        const changes = projectIds.map((id) => {
          const p = found.get(id);
          return { id: p?.id ?? id, name: p?.attributes?.name ?? "(no name)", changes: changesFor(stateOf(p), update) };
        });
        return { org_id: parsed.org_id, update, changes };
      },
      describeDryRun: async (data) => {
        const where = await formatOrgId(config, data.org_id);
        const toChange = data.changes.filter((c) => c.changes.length);
        const unchanged = data.changes.filter((c) => !c.changes.length);
        // The projects that will change come first, so the capped list can't fill up with
        // "no change" lines and push them out of sight; the unchanged ones are summarized.
        const lines = toChange.map((c) => `- ${c.name} (${c.id}): ${c.changes.join("; ")}`);
        const head = toChange.length
          ? `Dry run – will update ${toChange.length} of ${data.changes.length} project(s) in ${where} (one PATCH each; not atomic).`
          : `Dry run – nothing to change: all ${data.changes.length} project(s) in ${where} already have these values.`;
        const skipped = unchanged.length && toChange.length
          ? `\n\nSkipped, already set (${unchanged.length}): ${unchanged.slice(0, 10).map((c) => c.name).join(", ")}${unchanged.length > 10 ? `, …and ${unchanged.length - 10} more` : ""}`
          : "";
        return `${head}${lines.length ? `\n\n${capped(lines)}` : ""}${skipped}\n\nPlan:\n${JSON.stringify({ org_id: data.org_id, update: data.update, project_ids: toChange.map((c) => c.id) }, null, 2)}`;
      },
      apply: async (data) => {
        const toChange = data.changes.filter((c) => c.changes.length);
        const results = await Promise.all(
          toChange.map(async (c) => {
            try {
              await rest.updateProject(config, data.org_id, c.id, data.update);
              return { projectId: c.id, name: c.name, ok: true as const };
            } catch (err) {
              return { projectId: c.id, name: c.name, ok: false as const, error: err instanceof Error ? err.message : String(err) };
            }
          })
        );
        const failed = results.filter((r) => !r.ok).length;
        const skipped = data.changes.length - toChange.length;
        const summary = failed === 0
          ? `Updated ${results.length} project(s)${skipped ? `; ${skipped} already had these values` : ""}.`
          : `Updated ${results.length - failed} of ${results.length} project(s); ${failed} failed and are unchanged.`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});

// --- Project settings (V1): pull request checks and automatic fix / upgrade PRs ---

/** "a=1, b=x" for the keys of `s`, with nested objects flattened as parent.child. */
function flatEntries(s: Record<string, unknown>, prefix = ""): [string, unknown][] {
  return Object.entries(s).flatMap(([k, v]) =>
    v && typeof v === "object" && !Array.isArray(v) ? flatEntries(v as Record<string, unknown>, `${prefix}${k}.`) : [[`${prefix}${k}`, v] as [string, unknown]]
  );
}

const ListProjectSettingsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string().min(1)).min(1).max(100).describe("Project IDs (from snyk_list_projects)"),
});

/**
 * Read-only on purpose. Writing these through V1 PUT /org/{org}/project/{id}/settings was
 * live-tested (2026-11-10) on SAST, npm, and Secrets projects from the GitHub Cloud App and
 * GitLab integrations: every PUT answered 200 and changed nothing, including when
 * `pullRequestInheritance` was sent. Projects connected to a repo have
 * `pullRequestInheritance: "integration"`, so their pull request checks come from the
 * integration's settings; CLI projects have none. An update tool was built, caught this with
 * its read-back check, and was removed rather than shipped.
 */
export const listProjectSettings = defineTool({
  name: "snyk_list_project_settings",
  description: "Show projects' pull request check settings for Snyk Open Source and Snyk Code (V1), one line per project, including pullRequestInheritance: \"integration\" means the project uses its integration's settings (the usual case for projects imported from a repo). Use it to audit, e.g., which projects have PR checks off. CLI projects have no such settings. Read-only.",
  schema: ListProjectSettingsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const found = await requireProjectsInOrg(config, a.org_id, a.project_ids);
    const ids = [...new Set(a.project_ids.map((id) => id.toLowerCase()))];
    const rows = await Promise.all(ids.map(async (id) => {
      try {
        const s = await v1.getProjectSettings(config, a.org_id, id);
        const fields = flatEntries(s).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
        return `${nameOf(found.get(id), id)}: ${fields || "(no pull request check settings, e.g. a CLI project)"}`;
      } catch (err) {
        return `${nameOf(found.get(id), id)}: couldn't read settings (${err instanceof Error ? err.message : String(err)})`;
      }
    }));
    const where = await formatOrgId(config, a.org_id);
    return { content: [{ type: "text", text: `Settings for ${ids.length} project(s) in ${where}:\n\n${rows.join("\n")}` }], isError: false };
  },
});
