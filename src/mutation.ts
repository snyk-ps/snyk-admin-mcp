import { createApproval, consumeApproval } from "./approval.js";

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

interface MutationPlan<TData> {
  action: string;
  requestKey: string;
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
        text: `${description}\n\nTo apply, call this tool again with dry_run=false and approval_token="${approval_token}"`,
      }],
      isError: false,
    };
  }

  const stored = consumeApproval(opts.approvalToken ?? "") as MutationPlan<TData> | null;
  if (!stored || stored.action !== opts.action) {
    return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
  }
  if (stored.requestKey !== requestKey) {
    return {
      content: [{
        type: "text",
        text: "Arguments no longer match the approved plan (they changed since the dry run). Run with dry_run=true again to generate a fresh plan.",
      }],
      isError: true,
    };
  }
  const text = await opts.apply(stored.data);
  return { content: [{ type: "text", text }], isError: false };
}
