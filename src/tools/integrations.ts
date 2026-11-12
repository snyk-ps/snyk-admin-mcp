/**
 * Integration settings tools (V1): read and set the pull request check settings of one
 * integration type (e.g. github-cloud-app) across many orgs.
 *
 * This is where pull request checks are actually controlled: projects imported from a repo
 * inherit them from the integration (`pullRequestInheritance: "integration"`), and V1 ignores
 * writes to the project-level copy (see snyk_list_project_settings). Only the check settings are
 * writable here; the automatic fix / upgrade PR settings on the same integrations are left out,
 * because changing them makes Snyk open pull requests on customers' repositories.
 */
import { z } from "zod";
import * as v1 from "../snyk/v1.js";
import type { SnykApiConfig } from "../snyk/types.js";
import { runMutationTool } from "../mutation.js";
import { DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { formatOrgId } from "./format.js";

/** The settings this tool writes: pull request checks for Snyk Open Source, Snyk Code, and Snyk Secrets. */
const PR_CHECK_FIELDS = [
  "pullRequestTestEnabled",
  "pullRequestFailOnAnyVulns",
  "pullRequestFailOnlyForHighSeverity",
  "pullRequestFailOnlyForIssuesWithFix",
  "pullRequestTestCodeEnabled",
  "pullRequestTestCodeSeverity",
  "pullRequestFailOnAnyCodeIssues",
  "pullRequestTestSecretsEnabled",
  "pullRequestTestSecretsSeverity",
] as const;

const PrCheckSettingsSchema = z
  .object({
    pullRequestTestEnabled: z.boolean().optional().describe("Run Snyk Open Source checks on pull requests"),
    pullRequestFailOnAnyVulns: z.boolean().optional().describe("Fail the Open Source check on any vulnerability in the repo, not only ones the PR adds"),
    pullRequestFailOnlyForHighSeverity: z.boolean().optional().describe("Fail the Open Source check only for high and critical severity issues"),
    pullRequestFailOnlyForIssuesWithFix: z.boolean().optional().describe("Fail the Open Source check only for issues that have a fix"),
    pullRequestTestCodeEnabled: z.boolean().optional().describe("Run Snyk Code checks on pull requests"),
    pullRequestTestCodeSeverity: z.enum(["low", "medium", "high"]).optional().describe("Lowest Snyk Code severity that fails the check"),
    pullRequestFailOnAnyCodeIssues: z.boolean().optional().describe("Fail the Snyk Code check on any issue in the repo, not only ones the PR adds"),
    pullRequestTestSecretsEnabled: z.boolean().optional().describe("Run Snyk Secrets checks on pull requests"),
    pullRequestTestSecretsSeverity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Lowest Snyk Secrets severity that fails the check"),
  })
  .strict();

const IntegrationTypeSchema = z.string().min(1).describe("Integration type, as snyk_list_integrations shows it: e.g. github, github-cloud-app, github-enterprise, gitlab, bitbucket-cloud, bitbucket-connect-app, bitbucket-server, azure-repos");
const OrgIdsSchema = z.array(z.string().min(1)).min(1);

const show = (v: unknown) => (v === undefined ? "(not set)" : JSON.stringify(v));

/** For one org: that integration's ID and settings, or why it can't be used. */
async function lookUp(config: SnykApiConfig, orgId: string, type: string): Promise<{ id: string; settings: v1.IntegrationSettings } | { skip: string }> {
  // Fresh: an integration added (or cloned in) a moment ago must be found.
  const integrations = await v1.listIntegrations(config, orgId, { fresh: true });
  const id = integrations[type];
  if (!id) return { skip: `no ${type} integration (it has: ${Object.keys(integrations).join(", ") || "none"})` };
  const settings = await v1.getIntegrationSettings(config, orgId, id);
  if (!PR_CHECK_FIELDS.some((f) => f in settings)) return { skip: `its ${type} integration has no pull request check settings` };
  return { id, settings };
}

// --- List ---

const ListIntegrationSettingsArgsSchema = z.object({
  org_ids: OrgIdsSchema.max(25).describe("Org IDs to read (snyk_list_orgs gives a group's orgs)"),
  integration_type: IntegrationTypeSchema,
});

export const listIntegrationSettings = defineTool({
  name: "snyk_list_integration_settings",
  description: "Show one integration type's pull request check settings (Snyk Open Source, Snyk Code, and Snyk Secrets checks) in each of several orgs, plus its automatic fix and upgrade PR settings, one line per org. Projects imported from a repo inherit these, so this is what their PR checks actually follow. Read-only.",
  schema: ListIntegrationSettingsArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const orgIds = [...new Set(a.org_ids.map((id) => id.toLowerCase()))];
    const lines = await Promise.all(orgIds.map(async (orgId) => {
      const label = await formatOrgId(config, orgId);
      try {
        const found = await lookUp(config, orgId, a.integration_type);
        if ("skip" in found) return `${label}: ${found.skip}`;
        const s = found.settings;
        const checks = PR_CHECK_FIELDS.filter((f) => f in s).map((f) => `${f}=${JSON.stringify(s[f])}`).join(", ");
        const auto = s.autoRemediationPrs as Record<string, unknown> | undefined;
        const autoPrs = [
          `autoDepUpgradeEnabled=${JSON.stringify(s.autoDepUpgradeEnabled)}`,
          auto ? `autoRemediationPrs.freshPrsEnabled=${JSON.stringify(auto.freshPrsEnabled)}, autoRemediationPrs.backlogPrsEnabled=${JSON.stringify(auto.backlogPrsEnabled)}` : "",
        ].filter(Boolean).join(", ");
        return `${label} — ${a.integration_type} (${found.id}): ${checks}; automatic PRs: ${autoPrs}`;
      } catch (err) {
        return `${label}: couldn't read (${err instanceof Error ? err.message : String(err)})`;
      }
    }));
    return { content: [{ type: "text", text: `${a.integration_type} pull request check settings in ${orgIds.length} org(s):\n\n${lines.join("\n")}` }], isError: false };
  },
});

// --- Update ---

const UpdateIntegrationSettingsArgsSchema = z.object({
  org_ids: OrgIdsSchema.max(100).describe("Org IDs whose integration to update (snyk_list_orgs gives a group's orgs)"),
  integration_type: IntegrationTypeSchema,
  settings: PrCheckSettingsSchema.describe("Pull request check settings to set; ones you leave out are kept"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

type Change = { org_id: string; integration_id: string; body: Record<string, unknown>; lines: string[] };

export const updateIntegrationSettings = defineTool({
  name: "snyk_update_integration_settings",
  description: "Set the pull request check settings (Snyk Open Source, Snyk Code, and Snyk Secrets checks: on/off, fail conditions, severity thresholds) of one integration type, e.g. github-cloud-app, in each of many orgs (V1; one request per org). Projects imported from a repo inherit these, so this changes their PR checks. Only the settings you pass change. The dry run shows each org's current → new values and skips orgs already set or without that integration; after applying, each org's settings are read back and any that didn't take effect are reported. Automatic fix / upgrade PR settings aren't changed by this tool. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: UpdateIntegrationSettingsArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (parsed, config) => {
    const settings = Object.fromEntries(Object.entries(parsed.settings).filter(([, v]) => v !== undefined));
    if (Object.keys(settings).length === 0) {
      return { content: [{ type: "text", text: `Provide at least one setting: ${PR_CHECK_FIELDS.join(", ")}.` }], isError: true };
    }
    const orgIds = [...new Set(parsed.org_ids.map((id) => id.toLowerCase()))];
    type Plan = { integration_type: string; settings: Record<string, unknown>; changes: Change[]; unchanged: string[]; skipped: { org_id: string; why: string }[] };
    return await runMutationTool<Plan>({
      action: "update_integration_settings",
      toolName: "snyk_update_integration_settings",
      dryRun: parsed.dry_run,
      approvalToken: parsed.approval_token,
      bindingArgs: { org_ids: orgIds, integration_type: parsed.integration_type, settings },
      buildPlanData: async () => {
        const looked = await Promise.all(orgIds.map(async (orgId) => ({ orgId, found: await lookUp(config, orgId, parsed.integration_type) })));
        const changes: Change[] = [];
        const unchanged: string[] = [];
        const skipped: { org_id: string; why: string }[] = [];
        for (const { orgId, found } of looked) {
          if ("skip" in found) { skipped.push({ org_id: orgId, why: found.skip }); continue; }
          const body: Record<string, unknown> = {};
          const lines: string[] = [];
          for (const [k, v] of Object.entries(settings)) {
            if (JSON.stringify(found.settings[k]) !== JSON.stringify(v)) {
              body[k] = v;
              lines.push(`${k} ${show(found.settings[k])} → ${show(v)}`);
            }
          }
          if (lines.length) changes.push({ org_id: orgId, integration_id: found.id, body, lines });
          else unchanged.push(orgId);
        }
        return { integration_type: parsed.integration_type, settings, changes, unchanged, skipped };
      },
      describeDryRun: async (data) => {
        const label = (id: string) => formatOrgId(config, id);
        const lines = await Promise.all(data.changes.slice(0, 25).map(async (c) => `- ${await label(c.org_id)}: ${c.lines.join("; ")}`));
        const more = data.changes.length > 25 ? `\n- …and ${data.changes.length - 25} more (all in the plan below)` : "";
        const skipped = data.skipped.length
          ? `\n\nSkipped (${data.skipped.length}):\n${(await Promise.all(data.skipped.slice(0, 25).map(async (s) => `- ${await label(s.org_id)}: ${s.why}`))).join("\n")}`
          : "";
        const unchanged = data.unchanged.length ? `\n\nAlready set (${data.unchanged.length}): ${(await Promise.all(data.unchanged.slice(0, 10).map(label))).join(", ")}${data.unchanged.length > 10 ? `, …and ${data.unchanged.length - 10} more` : ""}` : "";
        const head = data.changes.length
          ? `Dry run – will update the ${data.integration_type} integration's pull request check settings in ${data.changes.length} org(s) (one request each; not atomic). Projects imported through it inherit these.`
          : `Dry run – nothing to change in the ${data.integration_type} integration of these ${orgIds.length} org(s).`;
        return `${head}${lines.length ? `\n\n${lines.join("\n")}${more}` : ""}${unchanged}${skipped}\n\nPlan:\n${JSON.stringify({ integration_type: data.integration_type, settings: data.settings, org_ids: data.changes.map((c) => c.org_id) }, null, 2)}`;
      },
      apply: async (data) => {
        const results = await Promise.all(data.changes.map(async (c) => {
          try {
            await v1.updateIntegrationSettings(config, c.org_id, c.integration_id, c.body);
            const after = await v1.getIntegrationSettings(config, c.org_id, c.integration_id);
            const notApplied = Object.entries(c.body).filter(([k, v]) => JSON.stringify(after[k]) !== JSON.stringify(v)).map(([k, v]) => `${k} (wanted ${show(v)}, now ${show(after[k])})`);
            return notApplied.length
              ? { org_id: c.org_id, integration_id: c.integration_id, ok: false as const, error: `accepted, but these didn't take effect: ${notApplied.join(", ")}` }
              : { org_id: c.org_id, integration_id: c.integration_id, ok: true as const };
          } catch (err) {
            return { org_id: c.org_id, integration_id: c.integration_id, ok: false as const, error: err instanceof Error ? err.message : String(err) };
          }
        }));
        const failed = results.filter((r) => !r.ok).length;
        const summary = results.length === 0
          ? "Nothing to change."
          : failed === 0
            ? `Updated the ${data.integration_type} integration in ${results.length} org(s); every setting was read back and matches.`
            : `Updated ${results.length - failed} of ${results.length} org(s); ${failed} failed or didn't fully take effect (see results).`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});
