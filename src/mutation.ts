import { createApproval, peekApproval, discardApproval } from "./approval.js";

/**
 * Shared dry-run/approve/apply engine for every mutating MCP tool. Each mutating tool's
 * handler in src/tools/ calls runMutationTool() instead of hand-rolling its own
 * "build plan -> stash token -> return text" / "redeem token -> apply" boilerplate. See
 * the runMutationTool doc comment below for the approval-binding guarantee this centralizes.
 */

/** The shape every tool handler in src/tools/ returns — plain text content plus an error flag. */
export interface ToolResult {
  content: { type: "text"; text: string }[];
  isError: boolean;
}

/** Recursively sort object keys so JSON.stringify is stable regardless of insertion order. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/** Stable key for binding an approval token to the exact arguments it was issued for. */
function requestKeyFor(bindingArgs: unknown): string {
  return JSON.stringify(canonicalize(bindingArgs));
}

/** What createApproval actually stores: which tool it's for, what it's bound to, and the payload to apply. */
interface MutationPlan<TData> {
  /** Matched against the calling tool's own action string, so a token from one tool can't be redeemed by another. */
  action: string;
  /** requestKeyFor(bindingArgs) at dry-run time; re-derived and compared at apply time. */
  requestKey: string;
  /** The tool-specific payload built by buildPlanData(), handed unchanged to apply(). */
  data: TData;
}

/**
 * Shared dry-run / approve / apply flow for mutating tools.
 *
 * `bindingArgs` must include every argument that determines what the mutation will
 * actually do (resolved scope/ids, payload, etc). The stored approval token is only
 * honored if the apply-time bindingArgs are identical to the ones the plan was built
 * from — this stops a token from applying a mutation whose displayed dry-run plan no
 * longer matches the arguments it's being applied with.
 */
export async function runMutationTool<TData>(opts: {
  action: string;
  /** The tool's own name (e.g. "snyk_copy_org_settings"), named explicitly in the dry-run footer so the caller doesn't have to guess which tool to re-invoke. */
  toolName: string;
  dryRun: boolean;
  approvalToken?: string;
  bindingArgs: unknown;
  buildPlanData: () => Promise<TData> | TData;
  describeDryRun: (data: TData) => Promise<string> | string;
  apply: (data: TData) => Promise<string> | string;
}): Promise<ToolResult> {
  const requestKey = requestKeyFor(opts.bindingArgs);

  if (opts.dryRun) {
    const data = await opts.buildPlanData();
    const plan: MutationPlan<TData> = { action: opts.action, requestKey, data };
    const approval_token = createApproval(plan);
    const description = await opts.describeDryRun(data);
    return {
      content: [{
        type: "text",
        text: `${description}\n\nTo apply, call ${opts.toolName} again with dry_run=false and approval_token="${approval_token}"`,
      }],
      isError: false,
    };
  }

  const token = opts.approvalToken ?? "";
  const stored = peekApproval(token) as MutationPlan<TData> | null;
  if (!stored || stored.action !== opts.action) {
    return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
  }
  if (stored.requestKey !== requestKey) {
    return {
      content: [{
        type: "text",
        text: "Arguments do not match the approved plan. Re-send the exact arguments from the dry run, or run with dry_run=true again to generate a fresh plan.",
      }],
      isError: true,
    };
  }
  // Consumed before applying so a client retry cannot execute the mutation twice.
  discardApproval(token);
  const text = await opts.apply(stored.data);
  return { content: [{ type: "text", text }], isError: false };
}
