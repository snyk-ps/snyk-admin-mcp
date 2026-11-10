/**
 * Ignore policy tools (REST Policies API, GA 2026-03-25): Snyk Code consistent ignores at org
 * level. Each policy ignores one Snyk Code finding across a repository, matched by the
 * finding's repository-level ID (`snyk/asset/finding/v1`) rather than a file and line.
 *
 * Copying is deliberately conservative, because an ignore hides a security finding:
 * only policies in effect are copied by default (not rejected, pending, or expired ones), and a
 * finding the target org already has a policy for is never given a second one.
 */
import { z } from "zod";
import * as rest from "../snyk/rest.js";
import { runMutationTool } from "../mutation.js";
import { DESTRUCTIVE, READ_ONLY, defineTool } from "./types.js";
import { formatOrgId, nextPageHint, pageCursors, pageLimitStep10 } from "./format.js";
import { sameOrgError } from "./guards.js";

const RFC3339 = z.iso.datetime({ offset: true });

/** The finding a policy matches (policies have at most one condition). */
const findingOf = (p: rest.IgnorePolicy) => p.attributes.conditions_group?.conditions?.[0]?.value ?? "(no condition)";
const expiresOf = (p: rest.IgnorePolicy) => p.attributes.action?.data?.expires;
const isExpired = (p: rest.IgnorePolicy, now: number) => {
  const e = expiresOf(p);
  return e !== undefined && Date.parse(e) <= now;
};

/** One line per policy: name, ID, type, expiry, review state, finding, who, when, reason. */
function describePolicy(p: rest.IgnorePolicy): string {
  const a = p.attributes;
  const expires = expiresOf(p) ? `expires ${expiresOf(p)}` : "never expires";
  const by = a.created_by?.name ? `; by ${a.created_by.name}${a.created_at ? ` on ${a.created_at.slice(0, 10)}` : ""}` : "";
  const reason = a.action?.data?.reason ? `; reason: ${a.action.data.reason.length > 120 ? `${a.action.data.reason.slice(0, 120)}…` : a.action.data.reason}` : "";
  return `${a.name} (${p.id}) — ${a.action?.data?.ignore_type ?? "?"}, ${expires}, review ${a.review ?? "?"}; finding ${findingOf(p)}${by}${reason}`;
}

// --- List ---

const ListIgnorePoliciesArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  search: z.string().optional().describe("Match the ignoring user's name or email, or the ignore type"),
  review: z.array(z.enum(rest.POLICY_REVIEW_STATES)).optional().describe("Only these review states"),
  expires_before: RFC3339.optional().describe("Only policies expiring before this time (RFC3339)"),
  expires_after: RFC3339.optional().describe("Only policies expiring after this time (RFC3339)"),
  expires_never: z.boolean().optional().describe("true = only policies that never expire"),
  order_by: z.enum(["created", "expires", "ignore-type", "requested-by"]).optional(),
  order_direction: z.enum(["asc", "desc"]).optional(),
  limit: pageLimitStep10("default 100 here"),
  starting_after: z.string().optional().describe("From next_starting_after"),
});

export const listIgnorePolicies = defineTool({
  name: "snyk_list_ignore_policies",
  description: "List an org's Snyk Code ignore policies (consistent ignores), one line each: name, policy ID, ignore type (wont-fix, temporary-ignore, not-vulnerable), expiry, review state, the finding it ignores (its repository-level finding ID), who created it, and the reason. Filter by review state, expiry, or the ignoring user. Only orgs with Snyk Code consistent ignores turned on have these. Read-only.",
  schema: ListIgnorePoliciesArgsSchema,
  annotations: READ_ONLY,
  handler: async (a, config) => {
    const data = await rest.listIgnorePolicies(config, a.org_id, {
      search: a.search,
      review: a.review,
      expires_before: a.expires_before,
      expires_after: a.expires_after,
      expires_never: a.expires_never,
      order_by: a.order_by,
      order_direction: a.order_direction,
      limit: a.limit ?? 100,
      starting_after: a.starting_after,
    });
    const policies = data.data ?? [];
    const pagination = pageCursors(data.links);
    const where = await formatOrgId(config, a.org_id);
    const header = `${policies.length} ignore polic${policies.length === 1 ? "y" : "ies"} in ${where}${pagination.next_starting_after ? " (more on the next page)" : ""}:`;
    const body = policies.length ? policies.map(describePolicy).join("\n") : "No ignore policies (or Snyk Code consistent ignores aren't turned on for this org).";
    return { content: [{ type: "text", text: `${header}\n\n${body}${nextPageHint(pagination.next_starting_after)}` }], isError: false };
  },
});

// --- Copy ---

const CopyIgnorePoliciesArgsSchema = z.object({
  source_org_id: z.string().describe("Org to copy ignore policies from"),
  target_org_id: z.string().describe("Org to create them in"),
  policy_ids: z.array(z.string().min(1)).min(1).max(1000).optional().describe("Copy only these policies (IDs from snyk_list_ignore_policies). Omit to copy every policy in effect"),
  include_pending: z.boolean().optional().describe("Also copy policies still pending review (default false: only approved or not-required ones)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

type Skipped = { id: string; name: string; why: string };
type CopyPlan = {
  source_org_id: string;
  target_org_id: string;
  create: { source_id: string; content: rest.IgnorePolicyContent; pending_in_source?: boolean }[];
  skipped: Skipped[];
};

export const copyIgnorePolicies = defineTool({
  name: "snyk_copy_ignore_policies",
  description: "Copy Snyk Code ignore policies (consistent ignores) from one org to another, e.g. when a repository is also scanned in another org. Copies every policy in effect, or just policy_ids. Skips rejected and expired policies, pending ones unless include_pending, and findings the target org already has a policy for. A copy only hides a finding where the target org scans the same repository, and the target org needs consistent ignores turned on. The new policies are created as this API token's user. Use dry_run=true first, then dry_run=false with approval_token to apply.",
  schema: CopyIgnorePoliciesArgsSchema,
  annotations: DESTRUCTIVE,
  handler: async (a, config) => {
    const sameOrg = sameOrgError(a.source_org_id, a.target_org_id);
    if (sameOrg) return sameOrg;
    const policyIds = a.policy_ids ? [...new Set(a.policy_ids.map((id) => id.toLowerCase()))] : null;
    return await runMutationTool<CopyPlan>({
      action: "copy_ignore_policies",
      toolName: "snyk_copy_ignore_policies",
      dryRun: a.dry_run,
      approvalToken: a.approval_token,
      bindingArgs: { source_org_id: a.source_org_id, target_org_id: a.target_org_id, policy_ids: policyIds, include_pending: a.include_pending ?? false },
      buildPlanData: async () => {
        const [source, target] = await Promise.all([rest.listAllIgnorePolicies(config, a.source_org_id), rest.listAllIgnorePolicies(config, a.target_org_id)]);
        let candidates = source;
        if (policyIds) {
          const byId = new Map(source.map((p) => [p.id.toLowerCase(), p]));
          const missing = policyIds.filter((id) => !byId.has(id));
          if (missing.length) {
            const where = await formatOrgId(config, a.source_org_id);
            throw new Error(`${missing.length} policy ID(s) not found in ${where}: ${missing.join(", ")}. Use snyk_list_ignore_policies to find them. Nothing was planned.`);
          }
          candidates = policyIds.map((id) => byId.get(id)!);
        }
        const now = Date.now();
        // Only target policies that are, or may become, in effect count as covering a finding:
        // an expired or rejected one doesn't ignore anything, so the source's policy is still needed.
        const targetFindings = new Map(
          target.filter((p) => p.attributes.review !== "rejected" && !isExpired(p, now)).map((p) => [findingOf(p), p])
        );
        const create: CopyPlan["create"] = [];
        const skipped: Skipped[] = [];
        const planned = new Set<string>();
        for (const p of candidates) {
          const finding = findingOf(p);
          const skip = (why: string) => skipped.push({ id: p.id, name: p.attributes.name, why });
          if (p.attributes.review === "rejected") skip("review rejected, so not in effect");
          else if (p.attributes.review === "pending" && !a.include_pending) skip("pending review (pass include_pending to copy it)");
          else if (isExpired(p, now)) skip(`expired ${expiresOf(p)}`);
          else if (targetFindings.has(finding)) {
            const existing = targetFindings.get(finding)!;
            skip(`target org already has a policy for this finding (${existing.attributes.name}${existing.attributes.review === "pending" ? ", pending review there" : ""})`);
          }
          else if (planned.has(finding)) skip("another policy in this copy already covers this finding");
          else {
            planned.add(finding);
            const { name, action_type, action, conditions_group } = p.attributes;
            create.push({ source_id: p.id, content: { name, action_type, action, conditions_group }, pending_in_source: p.attributes.review === "pending" });
          }
        }
        return { source_org_id: a.source_org_id, target_org_id: a.target_org_id, create, skipped };
      },
      describeDryRun: async (data) => {
        const [from, to] = await Promise.all([formatOrgId(config, data.source_org_id), formatOrgId(config, data.target_org_id)]);
        const lines = data.create.slice(0, 25).map((c) => {
          const d = c.content.action.data;
          return `- ${c.content.name}: ${d.ignore_type}, ${d.expires ? `expires ${d.expires}` : "never expires"}; finding ${c.content.conditions_group.conditions[0]?.value ?? "?"}${c.pending_in_source ? " (pending review in the source)" : ""}`;
        });
        const more = data.create.length > 25 ? `\n- …and ${data.create.length - 25} more (all in the plan below)` : "";
        const skipped = data.skipped.length
          ? `\n\nSkipped (${data.skipped.length}):\n${data.skipped.slice(0, 25).map((s) => `- ${s.name} (${s.id}): ${s.why}`).join("\n")}${data.skipped.length > 25 ? `\n- …and ${data.skipped.length - 25} more` : ""}`
          : "";
        const pending = data.create.filter((c) => c.pending_in_source).length;
        const pendingWarning = pending
          ? `\n\nWarning: ${pending} of these ${pending === 1 ? "is" : "are"} still pending review in ${from}. In ${to} ${pending === 1 ? "it" : "they"} may take effect straight away if that org doesn't require approval for ignores.`
          : "";
        const head = data.create.length
          ? `Dry run – will create ${data.create.length} ignore polic${data.create.length === 1 ? "y" : "ies"} in ${to}, copied from ${from} (one request each; not atomic). They will be created as this API token's user, and only hide findings where ${to} scans the same repository. The target org's ignore approval settings may put them in review.`
          : `Dry run – nothing to copy from ${from} to ${to}.`;
        return `${head}${lines.length ? `\n\n${lines.join("\n")}${more}` : ""}${pendingWarning}${skipped}\n\nPlan:\n${JSON.stringify({ source_org_id: data.source_org_id, target_org_id: data.target_org_id, copy_policy_ids: data.create.map((c) => c.source_id) }, null, 2)}`;
      },
      apply: async (data) => {
        const results: { source_id: string; name: string; ok: boolean; new_id?: string; error?: string }[] = [];
        // One at a time: a failure (e.g. consistent ignores off in the target org) usually
        // repeats for every policy, and the per-policy results say so either way.
        for (const c of data.create) {
          try {
            const created = await rest.createIgnorePolicy(config, data.target_org_id, c.content);
            results.push({ source_id: c.source_id, name: c.content.name, ok: true, new_id: created.id });
          } catch (err) {
            results.push({ source_id: c.source_id, name: c.content.name, ok: false, error: err instanceof Error ? err.message : String(err) });
          }
        }
        const failed = results.filter((r) => !r.ok).length;
        const to = await formatOrgId(config, data.target_org_id);
        const summary = results.length === 0
          ? `Nothing to copy to ${to}.`
          : failed === 0
            ? `Created ${results.length} ignore polic${results.length === 1 ? "y" : "ies"} in ${to}. Retest the target org's Snyk Code projects for the ignores to show.`
            : `Created ${results.length - failed} of ${results.length} ignore policies in ${to}; ${failed} failed.`;
        return `${summary}\n\nResults:\n${JSON.stringify(results, null, 2)}`;
      },
    });
  },
});
