/**
 * In-memory store for pending mutation plans awaiting apply. Backs the dry-run/approval
 * flow used by every mutating tool (see mutation.ts's runMutationTool): a dry run stashes
 * its plan here and hands back a token; applying later exchanges that token for the plan.
 * Deliberately process-local, not persisted — tokens don't survive a server restart, and
 * that's fine since a dry run costs nothing to redo.
 */

/** How long an unclaimed approval stays valid before it's treated as expired. */
const TTL_MS = 10 * 60 * 1000; // 10 minutes

/** A stashed plan awaiting `dry_run=false` with its token. */
interface PendingApproval {
  plan: unknown;
  createdAt: number;
}

const store = new Map<string, PendingApproval>();

/** Drop any entries past their TTL. Called on every store access so the map never grows unbounded. */
function prune(): void {
  const now = Date.now();
  for (const [id, p] of store.entries()) {
    if (now - p.createdAt > TTL_MS) store.delete(id);
  }
}

/** Stash a plan and return a fresh token a caller can later redeem via peekApproval/discardApproval. */
export function createApproval(plan: unknown): string {
  prune();
  const id = `snyk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  store.set(id, { plan, createdAt: Date.now() });
  return id;
}

/**
 * Look up a pending approval without consuming it, so a rejected apply (wrong tool,
 * changed arguments) leaves the token usable for a corrected retry. Expired tokens are
 * dropped and reported as missing. Call discardApproval once the plan is accepted.
 */
export function peekApproval(approvalToken: string): unknown {
  prune();
  const p = store.get(approvalToken);
  if (!p) return null;
  if (Date.now() - p.createdAt > TTL_MS) {
    store.delete(approvalToken);
    return null;
  }
  return p.plan;
}

/** Consume a pending approval, enforcing single use. */
export function discardApproval(approvalToken: string): void {
  store.delete(approvalToken);
}
