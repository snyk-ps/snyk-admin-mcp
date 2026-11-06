# Snyk Admin MCP Server

MCP server for managing the Snyk platform as a customer with group admin permissions.

## Features

- **Copy settings between organizations** – Copy org settings from a source org to a target.
- **Clone integration** – Clone an integration (with settings and credentials) from one org to another.
- **Create organization** – Create a new org, optionally copying settings from a template org.
- **Project tags** – Add or remove tags on many projects in one go.
- **Move projects** – Move one or more projects from a source org to a target org.
- **Asset labeling** – Search, look up, and label assets (class/labels/tags) — one at a time, or many at once. Covers repository, image, and package assets.
- **Asset inventory** – Filter an org's or group's asset inventory (repositories, container images, SBOMs), count assets by any field (e.g. public vs private repos, assets per org), and label up to 100 assets per request. Early Access.
- **Audit logs** – Search org or group audit logs by time range, user, project, or event type.
- **Collections** – List collections and their projects, create collections, rename them, and add or remove projects in batches of 100.
- **Dry run + approval** – Every mutation supports `dry_run=true` (default) to preview a plan first. Apply with `dry_run=false` and the `approval_token` returned from the dry run. Tokens expire after 10 minutes. The token guarantees that what's applied is exactly what was previewed; it is not a human sign-off — see [Workflow](#workflow-mutations).

## Setup

### 1. Build the MCP server

Requires Node.js 22 or later.

```bash
npm install
npm run build
```

### 2. Configure credentials and region

**Option A: Use a `.env` file (recommended)**

In the project root, create a `.env` file with your values:

```bash
# Create .env in project root with:
#   SNYK_API_TOKEN=your-snyk-api-token-here
#   SNYK_API_REGION=us-01
```

The server loads `.env` from the project root on startup. Do not commit `.env` (it is gitignored).

**Option B: Environment variables**

Set **SNYK_API_TOKEN** (or **SNYK_TOKEN**) and optionally **SNYK_API_REGION** in your shell or in your MCP client config. Values match Snyk's own [regional tenant names](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency): `us-01` (default — SNYK-US-01, the original tenant; pre-September-2024 and Free-plan accounts), `us-02` (SNYK-US-02, new US Enterprise/Pilot accounts), `eu-01` (SNYK-EU-01, Frankfurt), `au-01` (SNYK-AU-01, Australia). Not sure which one you're on? Check the URL you use to log into the Snyk web app — `app.snyk.io` is `us-01`, `app.us.snyk.io` is `us-02`, and so on.

### 3. Add the MCP server to your MCP client

This server talks over standard MCP **stdio**, so it works with any MCP-compatible client (Cursor, Claude Desktop, Claude Code, Windsurf, VS Code with MCP support, etc.) — not just the one shown below. Every client needs the same three things:

- **command**: `node`
- **args**: the absolute path to this repo's built `dist/index.js`
- **env** (optional): `SNYK_API_TOKEN` / `SNYK_API_REGION`, if you're not using a `.env` file

Most desktop clients (Cursor, Claude Desktop, Windsurf, Claude Code) use the same JSON shape in their config file:

```json
{
  "mcpServers": {
    "snyk-admin": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/snyk-admin-mcp/dist/index.js"]
    }
  }
}
```

Replace `/ABSOLUTE/PATH/TO/snyk-admin-mcp` with the real path to this repo (e.g. `/Users/you/Apps/snyk-admin-mcp`). If you use a `.env` file in the project root, you can omit `env`; the server loads credentials from it. To pass credentials from the client config instead, add an `"env"` block:

```json
"env": {
  "SNYK_API_TOKEN": "your-token",
  "SNYK_API_REGION": "us-01"
}
```

Some clients differ in config file location or key name (for example, VS Code's MCP support uses a `servers` key with a `"type": "stdio"` field instead of `mcpServers`) — check your client's own MCP docs for the exact file and key if the shape above doesn't match what it expects.

#### Example: Cursor

1. Open **Cursor → Settings → MCP** (or edit `~/.cursor/mcp.json`).
2. Add the server entry shown above to the `mcpServers` object, restart Cursor (or reload the MCP settings), and confirm `snyk-admin` shows as connected.

## Tools

| Tool | Description |
|------|-------------|
| `snyk_list_orgs` | List organizations. Read-only. Supports cursor pagination (`limit`, `starting_after`, `ending_before`) and filters (`group_id`, `is_personal`, `slug`, `name`). |
| `snyk_list_integrations` | List integrations for an org. Read-only. |
| `snyk_list_projects` | List projects for an org. Read-only. |
| `snyk_search_audit_logs` | Search audit logs for an org or group, filterable by time range, user, project, or event type. Read-only. |
| `snyk_create_organization` | Create a new Snyk organization. Optional: `group_id`, `source_org_id` (copy settings from a template org). Dry run / approval flow. |
| `snyk_copy_org_settings` | Copy org settings (V1), SAST settings, Open Source language settings, and Secrets settings (all REST; Secrets is Early Access/beta) from a source org to a target org. Dry run → plan + `approval_token`; then call again with `dry_run=false` and that token to apply. |
| `snyk_clone_integration` | Clone one integration from a source org to a target org (CLI integrations excluded). Same dry run / approval flow. |
| `snyk_add_project_tags` | Add tags to multiple projects at once. Same dry run / approval flow. |
| `snyk_remove_project_tags` | Remove tags (by key) from multiple projects at once. Same dry run / approval flow. |
| `snyk_move_projects` | Move one or more projects from a source org to a target org. Same dry run / approval flow. |
| `snyk_search_assets` | Search assets in a group with optional attribute filters. Read-only. |
| `snyk_get_asset` | Get a single asset by ID within a group. Read-only. |
| `snyk_list_asset_projects` | List projects related to an asset, with cursor pagination. Read-only. |
| `snyk_list_related_assets` | List assets related to an asset, with optional type filter and pagination. Read-only. |
| `snyk_update_assets` | Update class, labels, and/or tags on one or more assets (repos included). One request per asset. Dry run / approval flow. |
| `snyk_list_inventory_assets` | List or filter Inventory assets in an org or group (RSQL filter, sort, chosen fields), with the total count. Read-only. |
| `snyk_get_inventory_asset_counts` | Count Inventory assets grouped by one field (e.g. `visibility`, `class`, `org_id`), optionally filtered. Read-only. |
| `snyk_list_inventory_fields` | List the fields you can filter and group by, or suggested values for one field. Read-only. |
| `snyk_update_inventory_assets` | Set class and add/remove labels and tags on Inventory assets, 100 per all-or-nothing request. Dry run / approval flow. |
| `snyk_list_collections` | List collections in an org, with project and issue counts. Filter by name or `is_generated`; sort and paginate. Read-only. |
| `snyk_list_collection_projects` | List the projects in a collection (IDs, targets, issue counts). Filter by target, integration, or with/without issues. Read-only. |
| `snyk_create_collection` | Create a collection, optionally adding projects to it. Dry run / approval flow. |
| `snyk_update_collection` | Rename a collection and/or add or remove projects. Dry run / approval flow. |

## Notes

- **Labels vs. tags** – `labels` are flat strings, `tags` are key/value pairs; `snyk_update_assets` takes `add`/`remove` for both, so existing values are preserved unless removed explicitly. The API gives no provenance for labels, but Snyk mirrors every detected language into `labels` — so a label matching a `languages` key is auto-generated (verified across a 29-repo group, no exceptions); the rest is yours, an asset policy's, or occasionally an internal label the UI never shows (e.g. `new repository`).
- **Project tags ≠ asset labels** – `snyk_add_project_tags` / `snyk_remove_project_tags` tag *projects* via the V1 API. Use `snyk_update_assets` to label assets.
- **No batch endpoint, not atomic** – `snyk_update_assets`, the project-tag tools, and `snyk_move_projects` each issue one API call per item (concurrently, rate-limited); a partial failure leaves earlier items updated (for `snyk_move_projects`, that means some projects already moved and some still in the source org).
- **`snyk_move_projects` needs group-admin permissions**, and if the move crosses group boundaries it needs a personal API key rather than a service account key — no REST equivalent exists for this, only the V1 API has it.
- **`snyk_search_audit_logs` omits `api.access` events by default** — that's the API's own behavior, not a filter this server adds. Pass `events: ["api.access"]` explicitly if you need them. Provide exactly one of `org_id`/`group_id`, and `events`/`exclude_events` are mutually exclusive.
- **`snyk_copy_org_settings` copies four separate resources** – V1 org settings (only fields editable via `PUT /v1/org/{orgId}/settings`, e.g. `requestAccess`), SAST settings (Snyk Code enablement/autofix), Open Source language settings (per-ecosystem, e.g. npm/maven/pip), and Secrets settings (`secrets_enabled` — Early Access/beta) — the latter three via the REST API. Each is applied independently and reported per-step, so a failure on one (e.g. the beta Secrets endpoint) doesn't block the others; check the returned step list if the target org ends up partially configured. If the source org's Secrets settings can't be read at all (usually because the org doesn't have Snyk Secrets), the dry run says so and the Secrets step is skipped; the other three are still copied.
- **Source and target must be different orgs** – `snyk_copy_org_settings`, `snyk_move_projects`, and `snyk_clone_integration` reject the same org ID as both source and target before making any API call; it almost always means the IDs were mixed up.
- **Asset tools are group-scoped** – pass `group_id`, not an org ID (`snyk_list_orgs` returns each org's `group_id`).
- **Two asset APIs, two ID formats** – the `snyk_*_inventory_*` tools use Snyk's Inventory Assets API; the other asset tools (`snyk_search_assets`, `snyk_get_asset`, `snyk_update_assets`, …) use the Asset API. They're separate stores with different IDs — Inventory IDs are dashed UUIDs (`01a19e5b-cbc5-…`), Asset API IDs are 32 hex characters (`6246f602…`) — and neither API accepts the other's (both return 404). `snyk_update_inventory_assets` rejects an Asset API ID with a pointer to `snyk_update_assets`. **Labels and tags are separate too**: verified live, a repo with 9 labels in the Asset API had none in Inventory, and a label added through Inventory never showed up in the Asset API. Pick the API whose labels your other tooling reads.
- **When to use the Inventory tools** – for org-scoped listing, RSQL filters, counts by field, and updating many repositories or images in single all-or-nothing requests. Use the Asset API tools for package assets (Inventory has none) and for an asset's related projects and assets (Inventory's relationship endpoints returned empty lists live, so they aren't wrapped).
- **Inventory updates are batched, all-or-nothing per batch** – `snyk_update_inventory_assets` sends up to 100 assets per request; the API applies each request completely or not at all, but separate requests are independent. Its dry run first looks every ID up (and fails if any is unknown), because one unknown ID would fail its whole request. It only uses `add`/`remove` for labels and tags, never the API's replace-everything form.
- **Collections are org-scoped** – there is no group-level collection endpoint, so covering a whole group means one call per org. Projects must be in the collection's org.
- **Generated collections** – Snyk creates one collection per imported repository, named after it (e.g. `github.com/org/repo`) and flagged `is_generated`. Pass `is_generated: false` to `snyk_list_collections` to see only the ones people made. `snyk_update_collection` warns in its dry run before changing a generated one.
- **Collection changes are batched, not atomic** – the API takes up to 100 project IDs per add/remove request, so larger lists are split into batches and sent in order. If a batch fails, earlier batches stay applied; the result lists each step. For `snyk_create_collection`, the collection itself is kept even if adding projects fails.
- **The API ignores bad project IDs without an error** – adding an unknown project ID, or a project from a different org, still returns success but changes nothing. So after any add or remove, the collection tools re-read the collection (one request per 100 members) and list each project that didn't take effect under `not_added` / `not_removed`.
- **Collection projects come back without names** – the API returns project IDs, target IDs, and issue counts only; use `snyk_list_projects` to map IDs to names.
- **Rate limits** – throttled to ~90% of Snyk's limits (REST 1620/min, V1 2000/min), with automatic retry on 429.

## Workflow (mutations)

1. Call the tool with **`dry_run: true`** (default).
2. Review the returned plan and **`approval_token`**.
3. To apply, call the same tool with **`dry_run: false`** and **`approval_token`** set to that value.

Without a valid `approval_token`, the server will not perform the mutation.

**What the token does and doesn't guarantee.** The token ties the apply to the exact plan from the dry run: same tool, same arguments, within 10 minutes, usable once. It does **not** prove a person reviewed the plan — the AI receives the token in the dry-run output and can make the apply call itself. The human check is your MCP client asking before it runs a tool, so **keep confirmation on for the tools that change Snyk** (don't choose "always allow" for them).

To help clients do that, every tool is labelled in `tools/list` with MCP tool annotations:

| Label | Tools |
|-------|-------|
| Read-only (`readOnlyHint: true`) | all `list`, `get`, and `search` tools |
| Additive (`destructiveHint: false`) | `snyk_add_project_tags`, `snyk_create_organization`, `snyk_create_collection` |
| Destructive (`destructiveHint: true`) | `snyk_copy_org_settings`, `snyk_clone_integration`, `snyk_remove_project_tags`, `snyk_move_projects`, `snyk_update_assets`, `snyk_update_inventory_assets`, `snyk_update_collection` |

Clients that support annotations can run read-only tools freely and always confirm the rest. Annotations are hints; whether and how a client uses them depends on the client.

## License

Copyright 2026 Snyk Ltd. Licensed under the [Apache License, Version 2.0](LICENSE).
