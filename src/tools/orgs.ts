/**
 * Org-level tools: list orgs/integrations/projects, create an org, copy org settings,
 * and clone an integration between orgs.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import * as v1 from "../snyk/v1.js";
import { sanitizePathSegment } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { ADDITIVE, DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { sameOrgError } from "./guards.js";
import { describeProject, formatOrgId, formatIntegrationId, nextPageHint, pageCursors, pageLimitStep10 } from "./format.js";

// --- List orgs (REST) ---
const ListOrgsArgsSchema = z.object({
  limit: pageLimitStep10(),
  starting_after: z.string().optional().describe("From next_starting_after"),
  ending_before: z.string().optional().describe("From prev_ending_before"),
  group_id: z.string().optional().describe("Filter: only return orgs within this group"),
  is_personal: z.boolean().optional().describe("Filter: if true, only return orgs not part of any group"),
  slug: z.string().optional().describe("Filter: only return orgs whose slug exactly matches this value"),
  name: z.string().optional().describe("Filter: only return orgs whose name contains this value"),
});

// --- List integrations (V1) ---
const ListIntegrationsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
});

// --- List projects (REST) ---
/** A tag filter is `key:value`; the spec's pattern requires both parts. */
const ProjectTagFilterSchema = z.object({
  key: z.string().regex(/^[a-zA-Z0-9_-]+$/, "Tag keys are letters, digits, _ and -"),
  value: z.string().regex(/^[:/?#@&+=%a-zA-Z0-9_.~-]+$/, "Tag values are letters, digits, and :/?#@&+=%_.~-"),
});
/**
 * Snyk sends these filters comma-separated (`explode: false`), so a value containing a comma
 * would silently become two values. Rejected instead, with the reason.
 */
const NoCommaSchema = z.string().min(1).refine((v) => !v.includes(","), "Can't contain a comma: Snyk splits this filter on commas");
const ListProjectsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  names: z.array(NoCommaSchema).optional().describe("Only projects with exactly these names"),
  names_start_with: z.array(NoCommaSchema).optional().describe("Only projects whose name starts with one of these. For one repo's projects use \"owner/repo(\": the \"(\" stops a sibling repo such as owner/repo-api from matching too. Or filter by target_id"),
  tags: z.array(ProjectTagFilterSchema).optional().describe("Only projects that have every one of these tags"),
  origins: z.array(NoCommaSchema).optional().describe("Only these origins, e.g. github, github-cloud-app, gitlab, cli, docker-hub"),
  types: z.array(NoCommaSchema).optional().describe("Only these project types, e.g. npm, maven, sast, deb, terraformconfig"),
  target_id: z.array(z.guid()).optional().describe("Only projects in these targets"),
  target_reference: z.string().optional().describe("Only this branch or tag, e.g. main"),
  business_criticality: z.array(z.enum(rest.PROJECT_BUSINESS_CRITICALITY)).optional().describe("Only projects with all of these"),
  environment: z.array(z.enum(rest.PROJECT_ENVIRONMENT)).optional().describe("Only projects with all of these"),
  lifecycle: z.array(z.enum(rest.PROJECT_LIFECYCLE)).optional().describe("Only projects with all of these"),
  include_issue_counts: z.boolean().optional().describe("Add each project's latest critical/high/medium/low counts"),
  count_only: z.boolean().optional().describe("Return only how many projects match"),
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

// --- Copy org settings ---
const CopySettingsArgsSchema = z.object({
  source_org_id: z.string().describe("Source organization ID (to copy from)"),
  target_org_id: z.string().describe("Target organization ID (to copy to)"),
  dry_run: z.boolean().default(true).describe("If true, only return a plan; no changes. Set false and provide approval_token to apply."),
  approval_token: z.string().optional().describe("Required when dry_run is false; use the token returned from a prior dry run."),
});

// --- Clone integration ---
const CloneIntegrationArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID that has the integration"),
  integration_id: z.string().describe("Integration ID to clone"),
  target_org_id: z.string().describe("Organization ID to clone the integration into"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Create organization (V1) ---
const CreateOrganizationArgsSchema = z.object({
  name: z.string().describe("Name of the new organization"),
  group_id: z.string().optional().describe("Group ID to create the org under (required for Enterprise/group accounts)"),
  source_org_id: z.string().optional().describe("Optional template org ID to copy settings from"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

export const listOrgs = defineTool({
  name: "snyk_list_orgs",
  description: "List organizations accessible to the token, with each org's group_id (which the group-scoped tools need). Filter by group, name, slug, or personal; returns next_starting_after for the next page. Read-only.",
  schema: ListOrgsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const data = await rest.listOrgs(config, {
      limit: a.limit,
      starting_after: a.starting_after,
      ending_before: a.ending_before,
      group_id: a.group_id,
      is_personal: a.is_personal,
      slug: a.slug,
      name: a.name,
    });
    const lines = (data.data ?? []).map((org) => {
      const orgName = org.attributes?.name ?? "—";
      return `${orgName} (${org.id})`;
    });
    const summary = lines.length ? lines.join("\n") : "No organizations.";
    const nextCursor = rest.cursorFromLink(data.links?.next, "starting_after");
    const full = {
      data: data.data?.map((org) => ({
        id: org.id,
        name: org.attributes?.name ?? null,
        slug: org.attributes?.slug ?? null,
        group_id: org.attributes?.group_id ?? null,
      })),
      pagination: {
        next_starting_after: nextCursor,
        prev_ending_before: rest.cursorFromLink(data.links?.prev, "ending_before"),
        count: data.meta?.count ?? null,
      },
    };
    const nextHint = nextCursor
      ? `\n\nMore results: pass starting_after="${nextCursor}" (with the same filters) to get the next page.`
      : "";
    return {
      content: [{ type: "text", text: `${summary}${nextHint}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
      isError: false,
    };
  },
});

export const listIntegrations = defineTool({
  name: "snyk_list_integrations",
  description: "List integrations for an organization (V1 API). Read-only.",
  schema: ListIntegrationsArgsSchema,
  annotations: READ_ONLY,
  handler: async ({ org_id }, config) => {
    const data = await v1.listIntegrations(config, sanitizePathSegment(org_id, "org_id"));
    const orgName = await rest.getOrgName(config, org_id);
    const header = orgName ? `Integrations for ${orgName} (${org_id}):` : `Integrations for org ${org_id}:`;
    const lines = Object.entries(data).map(([typeName, id]) => `${typeName} (${id})`);
    const body = lines.length ? lines.join("\n") : "No integrations.";
    return {
      content: [{ type: "text", text: `${header}\n\n${body}\n\nRaw:\n${JSON.stringify(data, null, 2)}` }],
      isError: false,
    };
  },
});

export const listProjects = defineTool({
  name: "snyk_list_projects",
  description: "List an org's projects, one line each: name, ID, type, origin, branch, criticality/environment/lifecycle, and tags. Filter by name or name prefix (e.g. a repo), tags, origin, type, target, branch, or attributes; count_only returns just the number. Up to 100 per page; follow next_starting_after for more. Use it to find project IDs for the tag, move, collection, and snyk_update_projects tools. Read-only.",
  schema: ListProjectsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const orgId = sanitizePathSegment(a.org_id, "org_id");
    const filters = {
      names: a.names,
      names_start_with: a.names_start_with,
      tags: a.tags?.map((t) => `${t.key}:${t.value}`),
      origins: a.origins,
      types: a.types,
      target_id: a.target_id,
      target_reference: a.target_reference,
      business_criticality: a.business_criticality,
      environment: a.environment,
      lifecycle: a.lifecycle,
    };
    const orgLabel = await formatOrgId(config, orgId);
    const filtered = Object.values(filters).some((v) => (Array.isArray(v) ? v.length : v));
    const matching = filtered ? " matching the filters" : "";
    if (a.count_only) {
      const data = await rest.listProjects(config, orgId, { ...filters, count_only: true });
      return { content: [{ type: "text", text: `${data.meta?.count ?? "Unknown number of"} project(s) in ${orgLabel}${matching}.` }], isError: false };
    }
    const data = await rest.listProjects(config, orgId, {
      ...filters,
      latest_issue_counts: a.include_issue_counts,
      limit: a.limit ?? 100,
      starting_after: a.starting_after,
    });
    const projects = data.data ?? [];
    const pagination = pageCursors(data.links);
    const header = `${projects.length} project(s) in ${orgLabel}${matching}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    const body = projects.length ? projects.map(describeProject).join("\n") : "No projects.";
    return {
      content: [{ type: "text", text: `${header}\n\n${body}${nextPageHint(pagination.next_starting_after)}` }],
      isError: false,
    };
  },
});

export const createOrganization = defineTool({
  name: "snyk_create_organization",
  description: "Create a new Snyk organization. Uses Snyk V1 API (POST /org). Optional: group_id (required for group/Enterprise), source_org_id (copy settings from template). Use dry_run=true first, then dry_run=false with approval_token to execute.",
  schema: CreateOrganizationArgsSchema,
  annotations: ADDITIVE,
  handler: async (parsed, config) => {
    type CreateOrgPlan = { name: string; group_id: string; source_org_id?: string };
    return await runMutationTool<CreateOrgPlan>({
      action: "create_organization",
      toolName: "snyk_create_organization",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      // Bind on the raw group_id (possibly undefined), not a resolved value — resolving
      // rebinds on every apply call too, so a shifting org list between dry run and apply
      // could spuriously invalidate an otherwise-unchanged approval. Resolution only needs
      // to happen once, at dry-run time, and its result is frozen into the stored plan;
      // apply reads data.group_id from that plan and never re-resolves.
      bindingArgs: { name: parsed.name, group_id: parsed.group_id, source_org_id: parsed.source_org_id },
      buildPlanData: async () => {
        const resolvedGroupId = parsed.group_id ?? (await rest.getDefaultGroupId(config));
        if (!resolvedGroupId) {
          throw new Error("No group_id provided and none could be inferred (token may have only personal orgs or no orgs). Provide group_id explicitly, or use snyk_list_orgs to get an org's group_id from attributes.");
        }
        return { name: parsed.name, group_id: resolvedGroupId, source_org_id: parsed.source_org_id };
      },
      describeDryRun: async (data) => {
        const sourceOrgLabel = data.source_org_id ? ` (copying settings from ${await formatOrgId(config, data.source_org_id)})` : "";
        return `Dry run – will create organization "${data.name}" in group ${data.group_id}${sourceOrgLabel}.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
      },
      apply: async (data) => {
        const result = await v1.createOrganization(config, {
          name: data.name,
          group_id: sanitizePathSegment(data.group_id, "group_id"),
          source_org_id: data.source_org_id ? sanitizePathSegment(data.source_org_id, "source_org_id") : undefined,
        });
        const resultOrgName = (result as { name?: string }).name ?? (result as { id?: string }).id;
        return `Organization created: ${resultOrgName}. Result: ${JSON.stringify(result, null, 2)}`;
      },
    });
  },
});

export const copyOrgSettings = defineTool({
  name: "snyk_copy_org_settings",
  description: "Copy organization settings from a source org to a target org: V1 org settings (e.g. requestAccess) via Snyk's V1 API, plus SAST settings (whether Snyk Code is on), Open Source language settings, and Secrets settings (all via the REST API; Secrets settings is Early Access/beta). Always run with dry_run=true first to get a plan and approval_token, then run with dry_run=false and approval_token to apply.",
  schema: CopySettingsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const sameOrg = sameOrgError(parsed.source_org_id, parsed.target_org_id);
    if (sameOrg) return sameOrg;
    type CopySettingsPlan = {
      source_org_id: string;
      target_org_id: string;
      settings_to_apply: Record<string, unknown>;
      sast_settings_to_apply: rest.SastSettingsResource;
      language_settings_to_apply: rest.LanguageSettingsMap;
      /** null when the source org's Secrets settings couldn't be read; the reason is in secrets_settings_unavailable. */
      secrets_settings_to_apply: rest.SecretsSettingsResource | null;
      secrets_settings_unavailable?: string;
    };
    return await runMutationTool<CopySettingsPlan>({
      action: "copy_org_settings",
      toolName: "snyk_copy_org_settings",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { source_org_id: parsed.source_org_id, target_org_id: parsed.target_org_id },
      buildPlanData: async () => {
        const safeSourceOrgId = sanitizePathSegment(parsed.source_org_id, "source_org_id");
        const [settings_to_apply, sast_settings_to_apply, languageSettings, secrets] = await Promise.all([
          v1.getOrgSettings(config, safeSourceOrgId),
          rest.getSastSettings(config, safeSourceOrgId),
          rest.getLanguageSettings(config, safeSourceOrgId),
          // Secrets settings is a beta endpoint, and an org without Snyk Secrets can answer it
          // with a 403/404. That must not block copying the three GA setting groups, so a read
          // failure is recorded in the plan and the Secrets step is skipped on apply.
          rest.getSecretsSettings(config, safeSourceOrgId).then(
            (resource) => ({ resource, error: undefined }),
            (err: unknown) => ({ resource: null, error: err instanceof Error ? err.message : String(err) })
          ),
        ]);
        return {
          source_org_id: parsed.source_org_id,
          target_org_id: parsed.target_org_id,
          settings_to_apply,
          sast_settings_to_apply,
          language_settings_to_apply: languageSettings.attributes.languages ?? {},
          secrets_settings_to_apply: secrets.resource,
          ...(secrets.error !== undefined ? { secrets_settings_unavailable: secrets.error } : {}),
        };
      },
      describeDryRun: async (data) => {
        const sourceLabel = await formatOrgId(config, data.source_org_id);
        const targetLabel = await formatOrgId(config, data.target_org_id);
        const configured = Object.entries(data.language_settings_to_apply)
          .filter(([, packageManagers]) => Object.keys(packageManagers).length > 0)
          .map(([language]) => language);
        const emptyCount = Object.keys(data.language_settings_to_apply).length - configured.length;
        const languageSummary = configured.length
          ? `${configured.length} language setting(s): ${configured.join(", ")}`
          : "no language settings";
        const emptyNote = emptyCount ? `; ${emptyCount} language(s) skipped, nothing configured at the source` : "";
        const secretsSummary = data.secrets_settings_to_apply
          ? ` + Secrets settings [secrets_enabled=${data.secrets_settings_to_apply.attributes.secrets_enabled}]`
          : "";
        const secretsWarning = data.secrets_settings_to_apply
          ? ""
          : `\n\nSecrets settings will NOT be copied: they couldn't be read from the source org. Secrets settings is Early Access, so this usually means the source org doesn't have Snyk Secrets. The other settings are unaffected. Error: ${data.secrets_settings_unavailable}`;
        return `Dry run – copy settings from ${sourceLabel} to ${targetLabel} (V1 org settings + SAST settings + ${languageSummary}${emptyNote}${secretsSummary}).${secretsWarning}\n\nPlan:\n${JSON.stringify(data, null, 2)}\n\nNote: only requestAccess and similar editable fields are copied from V1 org settings; SAST, Open Source language, and Secrets settings are copied via the REST API (Secrets settings is Early Access/beta — version 2024-10-15~beta).`;
      },
      apply: async (data) => {
        const safeTargetOrgId = sanitizePathSegment(data.target_org_id, "target_org_id");
        // This writes to three separate endpoints and cannot be rolled back, so every step
        // is attempted and reported individually — a bare throw would leave the caller
        // unable to tell which settings actually landed on the target org.
        const steps: { step: string; ok: boolean; skipped?: boolean; note?: string; error?: string }[] = [];
        const record = async (step: string, run: () => Promise<unknown>) => {
          try {
            await run();
            steps.push({ step, ok: true });
          } catch (err) {
            steps.push({ step, ok: false, error: err instanceof Error ? err.message : String(err) });
          }
        };

        await record("org settings (V1)", () =>
          v1.updateOrgSettings(config, safeTargetOrgId, data.settings_to_apply)
        );
        await record("SAST settings", () =>
          rest.updateSastSettings(config, safeTargetOrgId, data.sast_settings_to_apply)
        );
        const secretsSettings = data.secrets_settings_to_apply;
        if (secretsSettings) {
          await record("Secrets settings", () =>
            rest.updateSecretsSettings(config, safeTargetOrgId, secretsSettings)
          );
        } else {
          steps.push({
            step: "Secrets settings",
            ok: true,
            skipped: true,
            note: `not copied: couldn't read the source org's Secrets settings (${data.secrets_settings_unavailable})`,
          });
        }
        await Promise.all(
          Object.entries(data.language_settings_to_apply).map(([language, packageManagers]) => {
            // `package_managers` is a oneOf across the six per-language schemas, and an empty
            // object matches all of them, so the API rejects `{}` with "must match exactly one
            // schema in oneOf". An empty object also means the source org has nothing
            // configured for that language, so there is genuinely nothing to copy.
            if (Object.keys(packageManagers).length === 0) {
              steps.push({
                step: `language settings (${language})`,
                ok: true,
                skipped: true,
                note: "source org has no package manager settings for this language",
              });
              return Promise.resolve();
            }
            return record(`language settings (${language})`, () =>
              rest.updateLanguageSettings(config, safeTargetOrgId, language, packageManagers)
            );
          })
        );

        const failed = steps.filter((s) => !s.ok);
        const skipped = steps.filter((s) => s.skipped);
        const applied = steps.length - failed.length - skipped.length;
        const targetLabel = await formatOrgId(config, data.target_org_id);
        const secretsSkipped = !secretsSettings;
        const languageSkips = skipped.length - (secretsSkipped ? 1 : 0);
        const skippedNote = languageSkips ? ` (${languageSkips} skipped — nothing configured at the source)` : "";
        const secretsNote = secretsSkipped ? " Secrets settings were not copied: they couldn't be read from the source org (see steps)." : "";
        const summary = failed.length === 0
          ? `Copied ${applied} setting group(s) to ${targetLabel}${skippedNote}.${secretsNote}`
          : `Copied ${applied} of ${steps.length - skipped.length} setting group(s) to ${targetLabel}${skippedNote}; ${failed.length} failed — the target org is partially configured.${secretsNote}`;
        return `${summary}\n\nSteps:\n${JSON.stringify(steps, null, 2)}`;
      },
    });
  },
});

export const cloneIntegration = defineTool({
  name: "snyk_clone_integration",
  description: "Clone an integration (with settings and credentials) from one organization to another. Uses Snyk V1 API. CLI integrations are not supported (rejected). Use dry_run=true first, then dry_run=false with approval_token to execute.",
  schema: CloneIntegrationArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const sameOrg = sameOrgError(parsed.source_org_id, parsed.target_org_id);
    if (sameOrg) return sameOrg;
    const safeSourceOrg = sanitizePathSegment(parsed.source_org_id, "source_org_id");
    const safeIntegrationId = sanitizePathSegment(parsed.integration_id, "integration_id");
    const integrationType = await v1.getIntegrationTypeName(config, safeSourceOrg, safeIntegrationId);
    if (v1.isCliIntegrationType(integrationType)) {
      return {
        content: [{
          type: "text",
          text: "CLI integration cannot be cloned via the API; skip it when copying integrations between organizations.",
        }],
        isError: true,
      };
    }
    type CloneIntegrationPlan = { source_org_id: string; integration_id: string; target_org_id: string };
    return await runMutationTool<CloneIntegrationPlan>({
      action: "clone_integration",
      toolName: "snyk_clone_integration",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { source_org_id: parsed.source_org_id, integration_id: parsed.integration_id, target_org_id: parsed.target_org_id },
      buildPlanData: () => ({
        source_org_id: parsed.source_org_id,
        integration_id: parsed.integration_id,
        target_org_id: parsed.target_org_id,
      }),
      describeDryRun: async (data) => {
        const sourceLabel = await formatOrgId(config, data.source_org_id);
        const targetLabel = await formatOrgId(config, data.target_org_id);
        const integrationLabel = await formatIntegrationId(config, data.source_org_id, data.integration_id);
        return `Dry run – clone integration ${integrationLabel} from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(data, null, 2)}`;
      },
      apply: async (data) => {
        const result = await v1.cloneIntegration(
          config,
          sanitizePathSegment(data.source_org_id, "source_org_id"),
          sanitizePathSegment(data.integration_id, "integration_id"),
          sanitizePathSegment(data.target_org_id, "target_org_id")
        );
        const doneTargetLabel = await formatOrgId(config, data.target_org_id);
        const doneIntegrationLabel = await formatIntegrationId(config, data.source_org_id, data.integration_id);
        return `Integration ${doneIntegrationLabel} cloned to ${doneTargetLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}`;
      },
    });
  },
});
