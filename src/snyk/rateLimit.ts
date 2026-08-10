/**
 * Per-minute rate limiter with sliding window. Ensures we stay under Snyk API limits:
 * REST 1620/min, V1 2000/min. Uses ~90% of limit for headroom.
 * Many concurrent callers are allowed; each acquires a slot before running.
 */

const WINDOW_MS = 60_000;

export interface RateLimiter {
  /** Run fn when a slot is available. Limits request starts per minute; concurrent requests allowed. */
  schedule<T>(fn: () => Promise<T>): Promise<T>;
}

/** Build a limiter that allows at most `requestsPerMinute` request starts in any trailing 60s window. */
function createSlidingWindowLimiter(requestsPerMinute: number): RateLimiter {
  const timestamps: number[] = [];
  const queue: Array<() => void> = [];
  let pumping = false;

  function prune(): void {
    const cutoff = Date.now() - WINDOW_MS;
    while (timestamps.length > 0 && timestamps[0]! < cutoff) timestamps.shift();
  }

  function waitForSlot(): Promise<void> {
    return new Promise((resolve) => {
      function tryAcquire(): void {
        prune();
        if (timestamps.length < requestsPerMinute) {
          timestamps.push(Date.now());
          resolve();
          return;
        }
        const waitMs = Math.max(100, (timestamps[0] ?? 0) + WINDOW_MS - Date.now());
        setTimeout(tryAcquire, waitMs);
      }
      tryAcquire();
    });
  }

  /**
   * Drain the queue one slot-wait at a time. `fn()` is deliberately not awaited before
   * recursing into `pump()` again — only *acquiring a slot* is serialized here, not the
   * request itself. That's what lets many requests be in flight concurrently while still
   * capping how many can *start* per minute (matches the module-level doc comment).
   */
  function pump(): void {
    if (pumping || queue.length === 0) return;
    pumping = true;
    waitForSlot().then(() => {
      const fn = queue.shift();
      pumping = false;
      if (fn) fn();
      pump();
    });
  }

  return {
    schedule<T>(fn: () => Promise<T>): Promise<T> {
      return new Promise((resolve, reject) => {
        queue.push(() => {
          fn().then(resolve, reject);
        });
        pump();
      });
    },
  };
}

/** REST API: 1620/min → use 1458/min (~90%) for headroom. */
export const restRateLimiter = createSlidingWindowLimiter(1458);

/** V1 API: 2000/min → use 1800/min (~90%) for headroom. */
export const v1RateLimiter = createSlidingWindowLimiter(1800);

const MAX_429_RETRIES = 3;

/** Parse Retry-After header (seconds or HTTP-date). Returns delay in ms. */
function getRetryAfterMs(response: Response): number {
  const v = response.headers.get("Retry-After");
  if (!v) return 5000;
  const n = parseInt(v, 10);
  if (!Number.isNaN(n)) return n * 1000;
  const d = new Date(v).getTime();
  if (!Number.isNaN(d)) return Math.max(1000, d - Date.now());
  return 5000;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Wrap fetch with 429 retry: on 429, wait Retry-After then retry up to MAX_429_RETRIES times. */
export async function fetchWithRetry(
  rateLimiter: RateLimiter,
  fetchFn: () => Promise<Response>
): Promise<Response> {
  return rateLimiter.schedule(async () => {
    let lastRes: Response | null = null;
    for (let attempt = 0; attempt <= MAX_429_RETRIES; attempt++) {
      const res = await fetchFn();
      if (res.status !== 429) return res;
      lastRes = res;
      const delay = getRetryAfterMs(res);
      await sleep(delay);
    }
    return lastRes!;
  });
}
