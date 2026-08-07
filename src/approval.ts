const TTL_MS = 10 * 60 * 1000; // 10 minutes

interface PendingApproval {
  plan: unknown;
  createdAt: number;
}

const store = new Map<string, PendingApproval>();

function prune(): void {
  const now = Date.now();
  for (const [id, p] of store.entries()) {
    if (now - p.createdAt > TTL_MS) store.delete(id);
  }
}

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
