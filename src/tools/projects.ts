/** Project tools: add/remove project tags and move projects between orgs (all V1 API). */
import { z } from "zod";
import * as v1 from "../snyk/v1.js";
import { sanitizePathSegment } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { ADDITIVE, DESTRUCTIVE, defineTool } from "./types.js";
import { formatOrgId } from "./format.js";
import { sameOrgError } from "./guards.js";

// --- Add project tags (V1 project tags). Not a real batch API — one HTTP call per project x tag. ---
const AddProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to apply tags to"),
  tags: z.array(z.object({
    key: z.string(),
    value: z.string().optional(),
  })).describe("Tags to add (key or key:value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Remove project tags (V1 project tags). Not a real batch API — one HTTP call per project x key. ---
const RemoveProjectTagsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to remove tags from"),
  tag_keys: z.array(z.string()).describe("Tag keys to remove (removal is by key only, no value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Move projects between orgs (V1). No REST equivalent, no batch endpoint — one HTTP call per project. ---
const MoveProjectsArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID the projects currently belong to"),
  target_org_id: z.string().describe("Organization ID to move the projects into"),
  project_ids: z.array(z.string()).min(1).describe("Project IDs to move"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

export const addProjectTags = defineTool({
  name: "snyk_add_project_tags",
  description: "Add tags to multiple projects (one V1 API call per project x tag, not a single batch request). Uses Snyk V1 API (project tags). Note: these are project tags, not asset labels — use snyk_update_assets for asset labels. Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
  schema: AddProjectTagsArgsSchema,
  annotations: ADDITIVE,
  handler: async (parsed, config) => {
    type AddProjectTagsPlan = { org_id: string; project_ids: string[]; tags: { key: string; value?: string }[] };
    return await runMutationTool<AddProjectTagsPlan>({
      action: "add_project_tags",
      toolName: "snyk_add_project_tags",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags },
      buildPlanData: () => ({ org_id: parsed.org_id, project_ids: parsed.project_ids, tags: parsed.tags }),
      describeDryRun: (data) => {
        const totalOperations = data.project_ids.length * data.tags.length;
        return `Dry run – will add ${data.tags.length} tag(s) to ${data.project_ids.length} project(s) (${totalOperations} operations).\n${JSON.stringify(data, null, 2)}`;
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
              return { projectId, tag, ok: false as const, error: String(err) };
            }
          })
        );
        return `Project tags added. Results:\n${JSON.stringify(results, null, 2)}`;
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
    type RemoveProjectTagsPlan = { org_id: string; project_ids: string[]; tag_keys: string[] };
    return await runMutationTool<RemoveProjectTagsPlan>({
      action: "remove_project_tags",
      toolName: "snyk_remove_project_tags",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys },
      buildPlanData: () => ({ org_id: parsed.org_id, project_ids: parsed.project_ids, tag_keys: parsed.tag_keys }),
      describeDryRun: (data) => {
        const totalOperations = data.project_ids.length * data.tag_keys.length;
        return `Dry run – will remove ${data.tag_keys.length} tag key(s) from ${data.project_ids.length} project(s) (${totalOperations} operations).\n${JSON.stringify(data, null, 2)}`;
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
              return { projectId, key, ok: false as const, error: String(err) };
            }
          })
        );
        return `Project tags removed. Results:\n${JSON.stringify(results, null, 2)}`;
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
    type MoveProjectsPlan = { source_org_id: string; target_org_id: string; project_ids: string[] };
    return await runMutationTool<MoveProjectsPlan>({
      action: "move_projects",
      toolName: "snyk_move_projects",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id, project_ids: parsed.project_ids },
      buildPlanData: () => ({ source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id, project_ids: parsed.project_ids }),
      describeDryRun: async (data) => {
        const sourceLabel = await formatOrgId(config, data.source_org_id);
        const targetLabel = await formatOrgId(config, data.target_org_id);
        return `Dry run – will move ${data.project_ids.length} project(s) from ${sourceLabel} to ${targetLabel} (one V1 API call per project; not atomic — a partial failure leaves some projects moved and some not). Requires group-admin permissions; moving across group boundaries needs a personal API key.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
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
