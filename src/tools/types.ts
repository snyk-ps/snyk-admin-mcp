/**
 * How a tool is defined. Every tool in src/tools/ is built with `defineTool`, so its name,
 * description, argument schema, and handler sit together in one place, and the same Zod
 * schema both validates a call and generates the `inputSchema` clients see in `tools/list`.
 */
import { z } from "zod";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import type { SnykApiConfig } from "../snyk/types.js";
import type { ToolResult } from "../mutation.js";

/**
 * MCP tool annotations, sent with each tool in `tools/list`. Clients that support them can
 * use them to decide when to ask the user before running a tool — e.g. run read-only tools
 * freely but always confirm destructive ones. They're hints, not enforcement: the
 * dry-run/approval flow (mutation.ts) is what binds an apply to the plan that was previewed.
 * Every tool must pick one of these, so a new tool can't ship without a label.
 */
/** Reads only; never changes anything in Snyk. */
export const READ_ONLY: ToolAnnotations = { readOnlyHint: true };
/** Changes Snyk, but only by adding (creating an org or collection, adding tags). */
export const ADDITIVE: ToolAnnotations = { readOnlyHint: false, destructiveHint: false };
/** Can overwrite or remove existing data (settings, tags, labels, memberships, project location). */
export const DESTRUCTIVE: ToolAnnotations = { readOnlyHint: false, destructiveHint: true };

/** A tool as the registry (tools/index.ts) sees it: catalog metadata plus `run`. */
export interface Tool {
  name: string;
  description: string;
  schema: z.ZodTypeAny;
  annotations: ToolAnnotations;
  /** Validate raw MCP arguments against `schema`, then call the handler. Throws on invalid arguments. */
  run(rawArgs: unknown, config: SnykApiConfig): Promise<ToolResult>;
}

/**
 * Define one tool. The handler receives arguments already parsed by `schema` (defaults
 * applied, types narrowed), so no handler calls `.parse()` itself.
 */
export function defineTool<S extends z.ZodTypeAny>(def: {
  name: string;
  description: string;
  schema: S;
  annotations: ToolAnnotations;
  handler: (args: z.infer<S>, config: SnykApiConfig) => Promise<ToolResult>;
}): Tool {
  return {
    name: def.name,
    description: def.description,
    schema: def.schema,
    annotations: def.annotations,
    run: (rawArgs, config) => def.handler(def.schema.parse(rawArgs ?? {}), config),
  };
}

/**
 * Convert a Zod args schema into the JSON Schema `tools/list` expects, so `inputSchema` is
 * always derived from the same Zod schema `.parse()` validates against instead of hand-kept
 * in sync with it. Uses Zod 4's built-in converter:
 * - `io: "input"` describes what a caller may send, so fields with a `.default()` (e.g.
 *   `dry_run`) stay optional rather than required.
 * - `target: "draft-7"` keeps the JSON Schema version this server has always published.
 * - Objects don't get `additionalProperties: false`, matching `.parse()`, which strips
 *   unknown keys rather than rejecting them.
 * `$schema` is dropped since it's meaningless nested inside a tool's `inputSchema`.
 */
export function toInputSchema(schema: z.ZodType): Record<string, unknown> {
  const { $schema, ...jsonSchema } = z.toJSONSchema(schema, { io: "input", target: "draft-7" }) as Record<string, unknown>;
  return jsonSchema;
}
