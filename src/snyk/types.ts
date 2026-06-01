export type SnykRegion = "global" | "eu" | "us" | "au";

export const REST_API_VERSION = "2024-10-15";

/** Version for the Asset API endpoints (Early Access). Newer than the default REST version. */
export const ASSET_API_VERSION = "2026-03-25";

/** Sanitize ID/path segment before use in API URLs to prevent SSRF. Returns validated string. */
export function sanitizePathSegment(value: string, label: string): string {
  if (!value || typeof value !== "string") throw new Error(`Invalid ${label}`);
  if (!/^[a-zA-Z0-9-]{1,128}$/.test(value) || value.includes("..")) {
    throw new Error(`Invalid ${label}: must be alphanumeric or UUID`);
  }
  return value;
}

/**
 * Sanitize a field/filter identifier used as a path segment (e.g. filter_id,
 * group_field_id). Allows dots and underscores (e.g. "tags.environment",
 * "asset_class") while still blocking path traversal and SSRF.
 */
export function sanitizeFieldSegment(value: string, label: string): string {
  if (!value || typeof value !== "string") throw new Error(`Invalid ${label}`);
  if (value.length > 128 || value.includes("..") || value.includes("/") || !/^[a-zA-Z0-9._-]+$/.test(value)) {
    throw new Error(`Invalid ${label}: must be alphanumeric with optional . _ -`);
  }
  return value;
}

export interface SnykApiConfig {
  token: string;
  /** Base URL without path, e.g. https://api.snyk.io or https://api.us.snyk.io */
  baseUrl?: string;
  /** If set, overrides baseUrl using known regions */
  region?: SnykRegion;
}

const REGION_HOSTS: Record<SnykRegion, string> = {
  global: "https://api.snyk.io",
  eu: "https://api.eu.snyk.io",
  us: "https://api.us.snyk.io",
  au: "https://api.au.snyk.io",
};

export function getBaseUrl(config: SnykApiConfig): { rest: string; v1: string } {
  if (config.baseUrl) {
    const base = config.baseUrl.replace(/\/$/, "");
    return { rest: `${base}/rest`, v1: `${base}/v1` };
  }
  const host = REGION_HOSTS[config.region ?? "global"];
  return { rest: `${host}/rest`, v1: `${host}/v1` };
}

/**
 * Origins this client is permitted to talk to. When an explicit baseUrl is
 * configured, only that origin is allowed; otherwise the known Snyk regional
 * API hosts are allowed.
 */
export function getAllowedOrigins(config: SnykApiConfig): string[] {
  if (config.baseUrl) {
    return [new URL(config.baseUrl).origin];
  }
  return Object.values(REGION_HOSTS).map((host) => new URL(host).origin);
}

/**
 * SSRF guard: ensure a request URL targets an allowed Snyk host over HTTPS
 * before it is ever passed to fetch(). Throws if the destination is not on the
 * allowlist, preventing requests from being redirected to attacker-controlled
 * or internal hosts. Returns the normalized URL string.
 */
export function assertAllowedUrl(config: SnykApiConfig, url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid request URL");
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`Refusing to make a non-HTTPS request to ${parsed.origin}`);
  }
  const allowed = getAllowedOrigins(config);
  if (!allowed.includes(parsed.origin)) {
    throw new Error(`Refusing to make a request to a disallowed host: ${parsed.origin}`);
  }
  return parsed.toString();
}
