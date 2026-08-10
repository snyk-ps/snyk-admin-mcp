/**
 * Shared config, URL-building, and security guards for both Snyk API clients
 * (REST in rest.ts, V1 in v1.ts). Nothing here talks to the network directly —
 * it's the plumbing every request goes through before `fetch()` is called.
 */

/**
 * Snyk's regional tenants, named to match Snyk's own docs
 * (https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency):
 * SNYK-US-01 (the original/default tenant — pre-September-2024 and Free-plan accounts),
 * SNYK-US-02 (new US Enterprise/Pilot accounts via automated provisioning), SNYK-EU-01
 * (Frankfurt), SNYK-AU-01 (Australia). SNYK-GOV-01 (Snyk for Government) exists but isn't
 * included here — Snyk's docs don't publish an API base URL for it, only a web app URL, so
 * there's nothing confirmed to point this client at.
 */
export type SnykRegion = "us-01" | "us-02" | "eu-01" | "au-01";

/** Default REST API version. Individual endpoints override this via `restFetch`'s `version` option when they need a newer or beta-only version. */
export const REST_API_VERSION = "2024-10-15";

/** Version for the Asset API endpoints (Early Access). Newer than the default REST version. */
export const ASSET_API_VERSION = "2026-03-25";

/**
 * Version for the Secrets Settings endpoints. Confirmed from the OpenAPI spec
 * (`x-snyk-api-version`): this is a `~beta` release, not the plain dated version
 * used elsewhere — passing the default REST_API_VERSION here would request a
 * version this beta-only resource doesn't exist under.
 */
export const SECRETS_SETTINGS_API_VERSION = "2024-10-15~beta";

/** Sanitize ID/path segment before use in API URLs to prevent SSRF. Returns validated string. */
export function sanitizePathSegment(value: string, label: string): string {
  if (!value || typeof value !== "string") throw new Error(`Invalid ${label}`);
  if (!/^[a-zA-Z0-9-]{1,128}$/.test(value) || value.includes("..")) {
    throw new Error(`Invalid ${label}: must be alphanumeric or UUID`);
  }
  return value;
}

/** Credentials and host selection passed to every REST/V1 client call in this server. */
export interface SnykApiConfig {
  /** Snyk API token, sent as `Authorization: token <token>` on every request. */
  token: string;
  /** Base URL without path, e.g. https://api.snyk.io or https://api.us.snyk.io */
  baseUrl?: string;
  /** If set, overrides baseUrl using known regions */
  region?: SnykRegion;
}

const REGION_HOSTS: Record<SnykRegion, string> = {
  "us-01": "https://api.snyk.io",
  "us-02": "https://api.us.snyk.io",
  "eu-01": "https://api.eu.snyk.io",
  "au-01": "https://api.au.snyk.io",
};

/** Resolve the REST and V1 base URLs (no trailing path) for a config's region or explicit `baseUrl` override. */
export function getBaseUrl(config: SnykApiConfig): { rest: string; v1: string } {
  if (config.baseUrl) {
    const base = config.baseUrl.replace(/\/$/, "");
    return { rest: `${base}/rest`, v1: `${base}/v1` };
  }
  const host = REGION_HOSTS[config.region ?? "us-01"];
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
