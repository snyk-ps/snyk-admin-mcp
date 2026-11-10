import { AsyncLocalStorage } from "node:async_hooks";
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

/** What a confirmation prompt came back with. "unavailable" means no prompt could be shown (client without elicitation, or turned off), so the token alone decides, as before. */
export type ConfirmResult = "confirmed" | "declined" | "unavailable";

/**
 * Per-call context from the transport layer (src/index.ts), carried to runMutationTool without
 * threading it through every tool handler.
 */
export interface ToolCallContext {
  /**
   * Ask the human, through the MCP client, to confirm an apply before it runs (MCP elicitation).
   * Throws if asking failed (e.g. the prompt timed out), and the apply is then not run.
   */
  confirm?: (request: { toolName: string; summary: string }) => Promise<ConfirmResult>;
}

const callContext = new AsyncLocalStorage<ToolCallContext>();

/** Run one tool call with this context available to runMutationTool. */
export function withToolCallContext<T>(ctx: ToolCallContext, fn: () => Promise<T>): Promise<T> {
  return callContext.run(ctx, fn);
}

/** Longest plan summary put in a confirmation prompt; the full plan was in the dry run. */
const MAX_CONFIRM_SUMMARY = 3000;

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
  /** The human-readable part of the dry-run text, shown again in the confirmation prompt. */
  summary: string;
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
    const description = await opts.describeDryRun(data);
    const readable = description.split("\n\nPlan:")[0];
    const summary = readable.length > MAX_CONFIRM_SUMMARY ? `${readable.slice(0, MAX_CONFIRM_SUMMARY)}…` : readable;
    const plan: MutationPlan<TData> = { action: opts.action, requestKey, data, summary };
    const approval_token = createApproval(plan);
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
  // The human check, when the client can show one: the token proves the apply matches the
  // previewed plan, but the AI holds it and can send it on its own. A confirmation prompt
  // (MCP elicitation) puts the decision in front of the person instead.
  const confirm = callContext.getStore()?.confirm;
  if (confirm) {
    let result: ConfirmResult;
    try {
      result = await confirm({ toolName: opts.toolName, summary: stored.summary });
    } catch (err) {
      return {
        content: [{
          type: "text",
          text: `Not applied: couldn't get a confirmation from you through the MCP client (${err instanceof Error ? err.message : String(err)}). Nothing was changed, and the approval token is still valid. If your client can't show confirmation prompts, set SNYK_ADMIN_CONFIRM=off in the server's environment.`,
        }],
        isError: true,
      };
    }
    if (result === "declined") {
      // A declined plan can't be re-sent with the same token; a deliberate retry needs a new dry run.
      discardApproval(token);
      return {
        content: [{ type: "text", text: "Not applied: the change was declined in the confirmation prompt. Nothing was changed. The approval token is no longer valid; run the dry run again if that was a mistake." }],
        isError: true,
      };
    }
  }
  // Consumed before applying so a client retry cannot execute the mutation twice.
  discardApproval(token);
  const text = await opts.apply(stored.data);
  return { content: [{ type: "text", text }], isError: false };
}
