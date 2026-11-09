/** Collection tools (REST, GA): list, list members, create, and update. Org-scoped. */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import type { SnykApiConfig } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { ADDITIVE, DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, pageCursors } from "./format.js";

// --- Collections (REST, GA). Org-scoped; no group-level endpoint exists. ---

const CollectionNameSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(rest.COLLECTION_NAME_PATTERN, "Collection names may only contain letters, digits, spaces, and _ - / : .");

// The add/remove endpoints validate every project ID as a UUID; checking here gives a clear
// error at dry-run time instead of a 400 partway through apply. `z.guid()` accepts any
// 8-4-4-4-12 hex ID, the same check Zod 3's `.uuid()` did; Zod 4's `.uuid()` additionally
// requires RFC version/variant digits, which could reject an ID the Snyk API itself accepts.
const CollectionProjectIdsSchema = z.array(z.guid("Project IDs must be UUIDs")).max(1000);

// The API's page size must be a multiple of 10 between 10 and 100.
const CollectionPageLimitSchema = z.number().int().min(10).max(100).multipleOf(10).optional()
  .describe("Results per page: 10-100, in steps of 10 (API default 10)");

const ListCollectionsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  name: z.string().max(255).optional().describe("Filter: only collections whose name contains this string"),
  is_generated: z.boolean().optional().describe("Filter: true = only Snyk-generated collections (one per imported repo), false = only user-created ones"),
  sort: z.enum(["name", "projectsCount", "issues"]).optional().describe("Sort field"),
  direction: z.enum(["ASC", "DESC"]).optional().describe("Sort direction (API default DESC)"),
  limit: CollectionPageLimitSchema,
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
});

const ListCollectionProjectsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  collection_id: z.string().describe("Collection ID (from snyk_list_collections)"),
  target_ids: z.array(z.guid()).max(25).optional().describe("Filter: only projects in these targets (max 25)"),
  integrations: z.array(z.string()).optional().describe("Filter: only projects from these integration types (e.g. github, gitlab, cli, ecr)"),
  show: z.array(z.enum(["vuln-groups", "clean-groups"])).optional().describe("Filter: vuln-groups = projects with issues, clean-groups = projects without"),
  sort: z.enum(["imported", "last_tested_at", "issues"]).optional().describe("Sort field"),
  direction: z.enum(["ASC", "DESC"]).optional().describe("Sort direction (API default DESC)"),
  limit: CollectionPageLimitSchema,
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
});

const CreateCollectionArgsSchema = z.object({
  org_id: z.string().describe("Organization ID to create the collection in"),
  name: CollectionNameSchema.describe("Collection name (1-255 chars: letters, digits, spaces, _ - / : .)"),
  project_ids: CollectionProjectIdsSchema.optional().describe("Optional project IDs (in the same org) to add right after creating it. Sent in batches of 100."),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

const UpdateCollectionArgsSchema = z.object({
  org_id: z.string().describe("Organization ID that owns the collection"),
  collection_id: z.string().describe("Collection ID (from snyk_list_collections)"),
  name: CollectionNameSchema.optional().describe("New name, to rename the collection"),
  add_project_ids: CollectionProjectIdsSchema.optional().describe("Project IDs (in the same org) to add. Sent in batches of 100."),
  remove_project_ids: CollectionProjectIdsSchema.optional().describe("Project IDs to remove. Sent in batches of 100."),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

/** Split a list into consecutive chunks of at most `size` items. */
function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** Drop duplicate IDs while keeping first-seen order, so a repeated ID can't cost an extra batch or trip a 409. */
function dedupe(ids: string[] | undefined): string[] {
  return [...new Set(ids ?? [])];
}

/** One step of a multi-request collection change, reported back per batch like snyk_copy_org_settings does. */
type CollectionStep = { step: string; ok: boolean; error?: string };

/**
 * Run add or remove batches in order, recording each one, and return the IDs from the
 * batches the API accepted. Batches run one after another rather than concurrently so a
 * failure report reads in the same order the plan listed them.
 */
async function runProjectBatches(
  steps: CollectionStep[],
  verb: "add" | "remove",
  ids: string[],
  run: (batch: string[]) => Promise<void>
): Promise<string[]> {
  const accepted: string[] = [];
  const batches = chunk(ids, rest.COLLECTION_PROJECTS_MAX_PER_REQUEST);
  for (const [i, batch] of batches.entries()) {
    const label = `${verb} ${batch.length} project(s)${batches.length > 1 ? ` (batch ${i + 1}/${batches.length})` : ""}`;
    try {
      await run(batch);
      steps.push({ step: label, ok: true });
      accepted.push(...batch);
    } catch (err) {
      steps.push({ step: label, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return accepted;
}

/** What re-reading a collection after a change found: accepted IDs that didn't actually take effect. */
type MembershipCheck = { not_added: string[]; not_removed: string[] } | { error: string };

/**
 * The add/remove endpoints answer 204 even for IDs they ignore — verified live: an unknown
 * project UUID and a project from a different org both "succeed" without changing
 * membership. So after a change, re-read the members and report which accepted IDs didn't
 * take. Costs one GET per 100 members.
 */
async function checkMembership(
  config: SnykApiConfig,
  orgId: string,
  collectionId: string,
  added: string[],
  removed: string[]
): Promise<MembershipCheck | null> {
  if (added.length === 0 && removed.length === 0) return null;
  try {
    const members = new Set(await rest.listAllCollectionProjectIds(config, orgId, collectionId));
    return { not_added: added.filter((id) => !members.has(id)), not_removed: removed.filter((id) => members.has(id)) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** One sentence on a membership check, or "" when everything took effect. */
function describeMembership(check: MembershipCheck | null): string {
  if (!check) return "";
  if ("error" in check) return ` Could not re-read the collection to confirm the changes took effect: ${check.error}`;
  const parts: string[] = [];
  if (check.not_added.length) parts.push(`${check.not_added.length} project(s) were not added`);
  if (check.not_removed.length) parts.push(`${check.not_removed.length} project(s) are still in the collection`);
  if (!parts.length) return "";
  return ` However, ${parts.join(" and ")}: the API accepted the request but ignored them. Usually that means the ID doesn't exist or the project belongs to a different org.`;
}

/** True when a membership check found nothing wrong (or there was nothing to check). */
function membershipClean(check: MembershipCheck | null): boolean {
  return !check || (!("error" in check) && check.not_added.length === 0 && check.not_removed.length === 0);
}

export const listCollections = defineTool({
  name: "snyk_list_collections",
  description: "List an org's project collections with project and issue counts (collections are per org: for a group, call once per org). Snyk makes one per imported repo (is_generated=true); is_generated=false shows only people-made ones. Filter by name, sort, and page. Read-only.",
  schema: ListCollectionsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const data = await rest.listCollections(config, a.org_id, {
      limit: a.limit,
      starting_after: a.starting_after,
      ending_before: a.ending_before,
      sort: a.sort,
      direction: a.direction,
      name: a.name,
      is_generated: a.is_generated,
    });
    const orgLabel = await formatOrgId(config, a.org_id);
    const collections = data.data ?? [];
    const lines = collections.map((c) => {
      const m = c.meta;
      const counts = m
        ? ` — ${m.projects_count} project(s); issues C${m.issues_critical_count} H${m.issues_high_count} M${m.issues_medium_count} L${m.issues_low_count}`
        : "";
      return `${c.attributes.name} (${c.id})${c.attributes.is_generated ? " [generated]" : ""}${counts}`;
    });
    const pagination = pageCursors(data.links);
    const full = {
      data: collections.map((c) => ({
        id: c.id,
        name: c.attributes.name,
        is_generated: c.attributes.is_generated ?? false,
        ...c.meta,
      })),
      pagination,
    };
    const body = lines.length ? lines.join("\n") : "No collections.";
    const nextHint = pagination.next_starting_after
      ? `\n\nMore results: pass starting_after="${pagination.next_starting_after}" to get the next page.`
      : "";
    return {
      content: [{ type: "text", text: `Collections in ${orgLabel}:\n\n${body}${nextHint}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});

export const listCollectionProjects = defineTool({
  name: "snyk_list_collection_projects",
  description: "List a collection's projects: IDs, target IDs, issue counts, import and last-test times, but not names (snyk_list_projects has those). Filter by target, integration, or with/without issues; sort and page. Read-only.",
  schema: ListCollectionProjectsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const data = await rest.listCollectionProjects(config, a.org_id, a.collection_id, {
      limit: a.limit,
      starting_after: a.starting_after,
      ending_before: a.ending_before,
      sort: a.sort,
      direction: a.direction,
      target_id: a.target_ids,
      show: a.show,
      integration: a.integrations,
    });
    const projects = data.data ?? [];
    const lines = projects.map((p) => {
      const m = p.meta;
      return `${p.id} — target ${p.relationships.target.data.id}; issues C${m.issues_critical_count} H${m.issues_high_count} M${m.issues_medium_count} L${m.issues_low_count}; last tested ${m.last_tested_at}`;
    });
    const pagination = pageCursors(data.links);
    const full = {
      data: projects.map((p) => ({ id: p.id, target_id: p.relationships.target.data.id, ...p.meta })),
      pagination,
    };
    const body = lines.length ? lines.join("\n") : "No projects in this collection (with these filters).";
    const nextHint = pagination.next_starting_after
      ? `\n\nMore results: pass starting_after="${pagination.next_starting_after}" to get the next page.`
      : "";
    return {
      content: [{ type: "text", text: `Projects in collection ${a.collection_id}:\n\n${body}${nextHint}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});

export const createCollection = defineTool({
  name: "snyk_create_collection",
  description: "Create a collection in an org, optionally adding projects from that org (100 per request; not atomic). The API silently skips unknown IDs and other orgs' projects, so the tool re-reads the collection and reports any that weren't added. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: CreateCollectionArgsSchema,
  annotations: ADDITIVE,
  handler: async (parsed, config) => {
    const projectIds = dedupe(parsed.project_ids);
    type CreateCollectionPlan = { org_id: string; name: string; project_ids: string[]; same_name_ids: string[] };
    return await runMutationTool<CreateCollectionPlan>({
      action: "create_collection",
      toolName: "snyk_create_collection",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, name: parsed.name, project_ids: projectIds },
      buildPlanData: async () => {
        // The name filter is a substring match, so narrow to exact matches. Only the first
        // page (100) is checked — this is a heads-up in the dry run, not a uniqueness guarantee.
        const existing = await rest.listCollections(config, parsed.org_id, { name: parsed.name, limit: 100 });
        const sameName = (existing.data ?? []).filter((c) => c.attributes.name === parsed.name).map((c) => c.id);
        return { org_id: parsed.org_id, name: parsed.name, project_ids: projectIds, same_name_ids: sameName };
      },
      describeDryRun: async (data) => {
        const orgLabel = await formatOrgId(config, data.org_id);
        const batches = Math.ceil(data.project_ids.length / rest.COLLECTION_PROJECTS_MAX_PER_REQUEST);
        const projectsNote = data.project_ids.length
          ? `, then add ${data.project_ids.length} project(s) in ${batches} batch(es) of up to ${rest.COLLECTION_PROJECTS_MAX_PER_REQUEST}`
          : " (empty)";
        const dupNote = data.same_name_ids.length
          ? `\n\nWarning: ${data.same_name_ids.length} collection(s) with this exact name already exist in this org (${data.same_name_ids.join(", ")}). Use snyk_update_collection to add projects to an existing one instead.`
          : "";
        return `Dry run – will create collection "${data.name}" in ${orgLabel}${projectsNote}.${dupNote}\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
      },
      apply: async (data) => {
        const created = await rest.createCollection(config, data.org_id, data.name);
        const steps: CollectionStep[] = [{ step: `create collection "${data.name}"`, ok: true }];
        const accepted = await runProjectBatches(steps, "add", data.project_ids, (batch) =>
          rest.addProjectsToCollection(config, data.org_id, created.id, batch)
        );
        const check = await checkMembership(config, data.org_id, created.id, accepted, []);
        const failed = steps.filter((s) => !s.ok);
        const added = check && !("error" in check) ? accepted.length - check.not_added.length : accepted.length;
        const summary = failed.length === 0
          ? `Created collection "${data.name}" (${created.id})${data.project_ids.length ? ` and added ${added} of ${data.project_ids.length} project(s)` : ""}.`
          : `Created collection "${data.name}" (${created.id}), but ${failed.length} of ${steps.length - 1} add batch(es) failed — the collection is missing those projects. Retry them with snyk_update_collection.`;
        const checkJson = check ? `\n\nMembership check:\n${JSON.stringify(check, null, 2)}` : "";
        return `${summary}${describeMembership(check)}\n\nSteps:\n${JSON.stringify(steps, null, 2)}${checkJson}`;
      },
    });
  },
});

export const updateCollection = defineTool({
  name: "snyk_update_collection",
  description: "Rename a collection and/or add or remove its projects (in that order, 100 per request; not atomic). The API silently skips unknown IDs and other orgs' projects, so the tool re-reads the collection and reports any that didn't change. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: UpdateCollectionArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const addIds = dedupe(parsed.add_project_ids);
    const removeIds = dedupe(parsed.remove_project_ids);
    if (parsed.name === undefined && addIds.length === 0 && removeIds.length === 0) {
      return {
        content: [{ type: "text", text: "Provide at least one of: name, add_project_ids, or remove_project_ids." }],
        isError: true,
      };
    }
    const removeSet = new Set(removeIds);
    const overlap = addIds.filter((id) => removeSet.has(id));
    if (overlap.length) {
      return {
        content: [{ type: "text", text: `These project IDs are in both add_project_ids and remove_project_ids: ${overlap.join(", ")}. Pick one.` }],
        isError: true,
      };
    }
    type UpdateCollectionPlan = {
      org_id: string;
      collection_id: string;
      current_name: string;
      is_generated: boolean;
      new_name?: string;
      add_project_ids: string[];
      remove_project_ids: string[];
    };
    return await runMutationTool<UpdateCollectionPlan>({
      action: "update_collection",
      toolName: "snyk_update_collection",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: {
        org_id: parsed.org_id,
        collection_id: parsed.collection_id,
        name: parsed.name,
        add_project_ids: addIds,
        remove_project_ids: removeIds,
      },
      buildPlanData: async () => {
        // Fetched once so the dry run fails fast on a wrong ID and can show the current name.
        const current = await rest.getCollection(config, parsed.org_id, parsed.collection_id);
        return {
          org_id: parsed.org_id,
          collection_id: parsed.collection_id,
          current_name: current.attributes.name,
          is_generated: current.attributes.is_generated ?? false,
          new_name: parsed.name,
          add_project_ids: addIds,
          remove_project_ids: removeIds,
        };
      },
      describeDryRun: async (data) => {
        const orgLabel = await formatOrgId(config, data.org_id);
        const ops: string[] = [];
        if (data.new_name !== undefined) ops.push(`rename to "${data.new_name}"`);
        if (data.add_project_ids.length) ops.push(`add ${data.add_project_ids.length} project(s)`);
        if (data.remove_project_ids.length) ops.push(`remove ${data.remove_project_ids.length} project(s)`);
        const generatedNote = data.is_generated
          ? "\n\nWarning: this is a Snyk-generated collection (one per imported repo, maintained by Snyk). Changes to it may be overwritten or rejected; prefer a user-created collection."
          : "";
        return `Dry run – collection "${data.current_name}" (${data.collection_id}) in ${orgLabel}: ${ops.join(", ")} (batches of up to ${rest.COLLECTION_PROJECTS_MAX_PER_REQUEST}; not atomic).${generatedNote}\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
      },
      apply: async (data) => {
        const steps: CollectionStep[] = [];
        if (data.new_name !== undefined) {
          try {
            await rest.renameCollection(config, data.org_id, data.collection_id, data.new_name);
            steps.push({ step: `rename to "${data.new_name}"`, ok: true });
          } catch (err) {
            steps.push({ step: `rename to "${data.new_name}"`, ok: false, error: err instanceof Error ? err.message : String(err) });
          }
        }
        const added = await runProjectBatches(steps, "add", data.add_project_ids, (batch) =>
          rest.addProjectsToCollection(config, data.org_id, data.collection_id, batch)
        );
        const removed = await runProjectBatches(steps, "remove", data.remove_project_ids, (batch) =>
          rest.removeProjectsFromCollection(config, data.org_id, data.collection_id, batch)
        );
        const check = await checkMembership(config, data.org_id, data.collection_id, added, removed);
        const failed = steps.filter((s) => !s.ok);
        const label = `"${data.new_name ?? data.current_name}" (${data.collection_id})`;
        const summary = failed.length === 0
          ? `Updated collection ${label}: all ${steps.length} request(s) were accepted${membershipClean(check) ? " and took effect" : ""}.`
          : `Updated collection ${label}: ${steps.length - failed.length} of ${steps.length} request(s) were accepted; ${failed.length} failed — the collection is partially updated.`;
        const checkJson = check ? `\n\nMembership check:\n${JSON.stringify(check, null, 2)}` : "";
        return `${summary}${describeMembership(check)}\n\nSteps:\n${JSON.stringify(steps, null, 2)}${checkJson}`;
      },
    });
  },
});
