# Snyk Admin MCP Server

An MCP server for Snyk group admins: copy org settings, clone integrations, create orgs, tag and move projects, label assets, manage collections, and search audit logs. Every change goes through a dry run first.

## Setup

Requires Node.js 22+.

```bash
npm install
npm run build
```

Create a `.env` in the project root (it's gitignored), or set the same variables in your MCP client config:

```bash
SNYK_API_TOKEN=your-snyk-api-token   # SNYK_TOKEN also works
SNYK_API_REGION=us-01                # optional, default us-01
```

Pick the region from the URL you sign in to ([Snyk regions](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency)):

| Region | Snyk web app | Tenant |
|--------|--------------|--------|
| `us-01` (default) | `app.snyk.io` | SNYK-US-01 |
| `us-02` | `app.us.snyk.io` | SNYK-US-02 |
| `eu-01` | `app.eu.snyk.io` | SNYK-EU-01 |
| `au-01` | `app.au.snyk.io` | SNYK-AU-01 |

Add it to any stdio MCP client (Claude Code, Claude Desktop, Cursor, Windsurf, …):

```json
{
  "mcpServers": {
    "snyk-admin": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/snyk-admin-mcp/dist/index.js"],
      "env": { "SNYK_API_TOKEN": "your-token", "SNYK_API_REGION": "us-01" }
    }
  }
}
```

Leave out `env` if you use `.env`. Some clients use a different shape; VS Code, for example, uses a `servers` key with `"type": "stdio"`.

## Tools

**Orgs, projects, audit logs**

| Tool | What it does |
|------|--------------|
| `snyk_list_orgs` | List orgs; filter by group, name, slug, personal. |
| `snyk_list_integrations` | List an org's integrations. |
| `snyk_list_projects` | List an org's projects. |
| `snyk_search_audit_logs` | Search org or group audit logs by time, user, project, event. |
| `snyk_create_organization` ✎ | Create an org, optionally copying settings from a template org. |
| `snyk_copy_org_settings` ✎ | Copy V1, SAST, Open Source language, and Secrets settings to another org. |
| `snyk_clone_integration` ✎ | Clone an integration, with credentials, to another org (not CLI). |
| `snyk_add_project_tags` ✎ / `snyk_remove_project_tags` ✎ | Add or remove tags on many projects. |
| `snyk_move_projects` ✎ | Move projects to another org. |

**Assets: Asset API** (group scope; repositories, images, packages)

| Tool | What it does |
|------|--------------|
| `snyk_search_assets` | Search assets with attribute filters. |
| `snyk_get_asset` | Get one asset. |
| `snyk_list_asset_projects` / `snyk_list_related_assets` | An asset's projects or related assets. |
| `snyk_update_assets` ✎ | Set class, add or remove labels and tags (one request per asset). |

**Assets: Inventory API** (Early Access; org or group scope; repositories, images, SBOMs)

| Tool | What it does |
|------|--------------|
| `snyk_list_inventory_assets` | List or filter assets (RSQL), with the total count. |
| `snyk_get_inventory_asset_counts` | Count assets by one field, e.g. `visibility` or `class`. |
| `snyk_list_inventory_fields` | Fields you can filter or group by, or suggested values for one. |
| `snyk_update_inventory_assets` ✎ | Set class, add or remove labels and tags, 100 assets per request. |

**Collections** (org scope)

| Tool | What it does |
|------|--------------|
| `snyk_list_collections` | List collections with project and issue counts. |
| `snyk_list_collection_projects` | List a collection's projects. |
| `snyk_create_collection` ✎ | Create a collection, optionally with projects. |
| `snyk_update_collection` ✎ | Rename a collection; add or remove projects. |

✎ = changes Snyk; uses the dry-run flow below.

## Changes: dry run, then apply

1. Call the tool with `dry_run: true` (the default). It returns a plan and an `approval_token`.
2. Call it again with `dry_run: false` and that token.

The token only applies the exact plan that was previewed (same tool and arguments, within 10 minutes, once). It is **not** a human sign-off: the AI receives the token and can make the apply call itself. The human check is your MCP client's confirmation prompt, so **don't "always allow" the ✎ tools**.

To help with that, every tool carries MCP annotations: read-only for `list`/`get`/`search` tools; additive (`destructiveHint: false`) for `snyk_create_organization`, `snyk_create_collection`, and `snyk_add_project_tags`; destructive for the other ✎ tools.

## Notes

**General**
- Requests are throttled to about 90% of Snyk's rate limits and retried on 429.
- Bulk changes aren't atomic: if one item fails, earlier items stay changed. Results list each item or batch.
- Copy, move, and clone refuse the same org as source and target.
- Group-scoped tools take a `group_id`; `snyk_list_orgs` shows each org's.

**Orgs and projects**
- `snyk_copy_org_settings` applies its four parts separately and reports each one. For V1 settings it copies only the fields the API lets you edit (e.g. `requestAccess`). If the source org's Secrets settings can't be read (usually because it has no Snyk Secrets), that part is skipped.
- `snyk_move_projects` needs group admin. Moving across groups needs a personal API key, not a service account key.
- Project tags (`snyk_*_project_tags`) are not asset labels.
- Audit log search leaves out `api.access` events unless you ask for them in `events`.

**Assets**
- **The Asset API and Inventory API are separate stores.** IDs differ (Asset API: 32 hex characters; Inventory: dashed UUIDs), and neither API accepts the other's. Labels and tags are separate too: a label set in one doesn't show in the other. `snyk_update_inventory_assets` rejects Asset API IDs.
- Use the Asset API tools for packages and an asset's related projects or assets. Use the Inventory tools for org scope, RSQL filters, counts, and labelling many assets in fewer requests.
- Inventory updates are all-or-nothing per 100-asset request. The dry run checks every ID exists first, and the tool only adds or removes labels and tags, never replaces them all.
- Labels are plain strings; tags are key/value pairs. Snyk copies each detected language into an asset's `labels`, so labels matching its languages are automatic.

**Collections**
- There is no group-level endpoint; covering a group means one call per org. Projects must be in the collection's org.
- Snyk generates one collection per imported repo (`is_generated`); filter with `is_generated: false` to see only people-made ones.
- The API silently ignores unknown project IDs and projects from other orgs, so the tools re-read the collection after a change and report `not_added` / `not_removed`.
- Collection project lists have IDs and issue counts but no names; use `snyk_list_projects` for names.

## License

Copyright 2026 Snyk Ltd. Licensed under the [Apache License, Version 2.0](LICENSE).
