# Snyk Admin MCP Server

MCP server for managing the Snyk platform as a customer with group admin permissions. Uses Snyk’s **REST API** and **V1 API** and routes each use case to the correct endpoint.

## Features

- **Copy settings between organizations** – Copy org settings from a source org to a target (V1 API).
- **Clone integration** – Clone an integration (with settings and credentials) from one org to another (V1 API).
- **Bulk asset labels** – Add labels (project tags) to many projects in one go (V1 API).
- **Asset API** – Search assets, look up an asset and its related projects/assets, update an asset's class/labels/tags, and manage repository aliases (REST API, Early Access).
- **Inventory Assets API** – List/search inventory assets (sync + async), get/update a single asset, list its projects/targets, and discover filter/group fields, across tenant/org/group scope (REST API, Early Access).
- **Dry run** – Every mutation tool supports `dry_run=true` (default) to return a plan only.
- **User approval** – To apply changes, call the same tool with `dry_run=false` and the `approval_token` returned from the dry run. Tokens expire after 10 minutes.

## API routing

| Use case | API | Notes |
|----------|-----|--------|
| List orgs, list projects | REST | `GET /orgs`, `GET /orgs/{id}/projects` with `version=2024-10-15` |
| Create organization | V1 | `POST /org` (name, optional groupId, optional sourceOrgId) |
| Org settings (get/update) | V1 | `GET/PUT org/{orgId}/settings` |
| Integrations (list, clone) | V1 | `GET org/{orgId}/integrations`, `POST .../integrations/{id}/clone` |
| Project tags/labels | V1 | `POST org/{orgId}/project/{projectId}/tags` |
| Search assets | REST | `POST /groups/{group_id}/assets/search` (Asset API, `version=2026-03-25`) |
| Get asset / related projects / related assets | REST | `GET /groups/{group_id}/assets/{asset_id}` and `.../relationships/{projects,assets}` |
| Update asset (class, labels, tags) | REST | `PATCH /groups/{group_id}/assets/{asset_id}` |
| Repository aliases (list, add, remove) | REST | `GET/POST/DELETE /{groups\|orgs}/{id}/assets/repository/aliases` |
| List/search inventory assets (sync) | REST | `GET /{tenants\|orgs\|groups}/{id}/inventory/assets` (RSQL `filter`) |
| Get / update inventory asset | REST | `GET`/`PATCH .../inventory/assets/{asset_id}` |
| Inventory asset projects / targets | REST | `GET .../inventory/assets/{asset_id}/relationships/{projects,targets}` |
| Async inventory search | REST | `POST .../inventory/assets/searches`, `GET .../searches/{search_id}/results` |
| Inventory filters / groups discovery | REST | `GET .../inventory/assets/{filters,groups}` and `.../{filter_id\|group_field_id}/values` |

## Setup

### 1. Build the MCP server

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
#   SNYK_API_REGION=global
```

The server loads `.env` from the project root on startup. Do not commit `.env` (it is gitignored).

**Option B: Environment variables**

Set **SNYK_API_TOKEN** (or **SNYK_TOKEN**) and optionally **SNYK_API_REGION** (`global` | `eu` | `us` | `au`) in your shell or in your MCP client config.

### 3. Add the MCP server to Cursor

“Adding a server to run index.js” means telling Cursor to **start your MCP server as a subprocess**: Cursor will run `node …/dist/index.js` and talk to it over stdio. You only need to add one MCP server entry.

1. Open **Cursor → Settings → MCP** (or edit `~/.cursor/mcp.json`).
2. Add a server entry that runs the built `index.js`:

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

Replace `/ABSOLUTE/PATH/TO/snyk-admin-mcp` with the real path to this repo (e.g. `/Users/you/Apps/snyk-admin-mcp`). If you use a `.env` file in the project root, you can omit `env`; the server loads credentials from it. To pass credentials from Cursor instead, add an `"env"` block:

```json
"env": {
  "SNYK_API_TOKEN": "your-token",
  "SNYK_API_REGION": "global"
}
```

## Tools

| Tool | Description |
|------|-------------|
| `snyk_list_orgs` | List organizations (REST). Read-only. |
| `snyk_list_integrations` | List integrations for an org (V1). Read-only. |
| `snyk_list_projects` | List projects for an org (REST). Read-only. |
| `snyk_create_organization` | Create a new Snyk organization (V1). Optional: `group_id`, `source_org_id` (copy settings from template). Dry run / approval flow. |
| `snyk_copy_org_settings` | Copy org settings from source to target. Dry run → plan + `approval_token`; then call with `dry_run=false` and that token to apply. |
| `snyk_clone_integration` | Clone one integration from source org to target org (CLI integration excluded). Same dry run / approval flow. |
| `snyk_bulk_asset_labels` | Add labels to multiple projects. Same dry run / approval flow. |
| `snyk_bulk_update_inventory_assets` | Bulk update inventory assets (class, labels, tags) via REST Inventory Assets API. Dry run / approval flow. |
| `snyk_search_assets` | Search assets in a group with optional attribute filters (REST Asset API). Read-only. |
| `snyk_get_asset` | Get a single asset by ID within a group (REST Asset API). Read-only. |
| `snyk_list_asset_projects` | List projects related to an asset, with cursor pagination (REST Asset API). Read-only. |
| `snyk_list_related_assets` | List assets related to an asset, with optional type filter and pagination (REST Asset API). Read-only. |
| `snyk_update_asset` | Update an asset's class, labels, and/or tags (REST Asset API). Dry run / approval flow. |
| `snyk_list_repository_aliases` | List repository aliases for a group or org (REST Asset API). Read-only. |
| `snyk_add_repository_alias` | Add repository aliases for a group or org (REST Asset API). Dry run / approval flow. |
| `snyk_remove_repository_alias` | Remove repository aliases from a group or org (REST Asset API). Dry run / approval flow. |
| `snyk_list_inventory_assets` | List/search inventory assets synchronously with an RSQL `filter` (REST Inventory Assets API). Read-only. |
| `snyk_get_inventory_asset` | Get a single inventory asset by ID (REST Inventory Assets API). Read-only. |
| `snyk_update_inventory_asset` | Update one inventory asset's class/labels/tags (REST Inventory Assets API). Dry run / approval flow. |
| `snyk_list_inventory_asset_projects` | List projects for an inventory asset (REST Inventory Assets API). Read-only. |
| `snyk_list_inventory_asset_targets` | List targets for an inventory asset (REST Inventory Assets API). Read-only. |
| `snyk_create_inventory_asset_search` | Create an async inventory asset search; returns a `search_id` (REST Inventory Assets API). Read-only. |
| `snyk_get_inventory_asset_search_results` | Fetch results for an async inventory search by `search_id` (REST Inventory Assets API). Read-only. |
| `snyk_list_inventory_asset_filters` | List available filter fields for inventory assets (REST Inventory Assets API). Read-only. |
| `snyk_get_inventory_asset_filter_values` | Autocomplete filter values for a filter field (REST Inventory Assets API). Read-only. |
| `snyk_list_inventory_asset_groups` | List available group fields for inventory assets (REST Inventory Assets API). Read-only. |
| `snyk_get_inventory_asset_group_values` | Aggregate group values for a group field (REST Inventory Assets API). Read-only. |

## Asset API notes

- The Asset API is **group-scoped** for search, lookup, relationships, and updates: pass `group_id` (a group UUID), not an org ID.
- Repository alias tools (`snyk_*_repository_alias`, `snyk_list_repository_aliases`) accept **either** `group_id` **or** `org_id` (exactly one).
- Search supports nested filters: a single `{ attribute, operator, values }` node, or a logical `and`/`or` node whose `values` array contains nested filter nodes. Filterable attributes include `name`, `type`, `class`, `labels`, `tags.<key>`, `repository_url`, and others.
- These endpoints are Early Access and use REST API `version=2026-03-25`.

## Inventory Assets API notes

- These tools accept **exactly one** scope: `tenant_id`, `org_id`, or `group_id`. The same `/inventory/assets/...` paths exist under all three scopes.
- Filtering uses **RSQL** (e.g. `type==container_images;class==A`, `created_at=gt=2026-01-01`), passed via the `filter` parameter — different from the Asset API's nested JSON filters.
- `snyk_create_inventory_asset_search` + `snyk_get_inventory_asset_search_results` implement the **asynchronous** search flow (create a search, then poll its results); `snyk_list_inventory_assets` is the synchronous variant.
- `snyk_update_inventory_asset` currently targets the `container_images` resource type (the only type the PATCH endpoint accepts). `labels`/`tags` accept either `{ add, remove }` or `{ replace }`.
- Sparse fieldsets are supported via the `fields` parameter (comma-separated `container_images` fields).
- These endpoints are Early Access and use REST API `version=2026-03-25`.

## Workflow (mutations)

1. Call the tool with **`dry_run: true`** (default).
2. Review the returned plan and **`approval_token`**.
3. To apply, call the same tool with **`dry_run: false`** and **`approval_token`** set to that value.

Without a valid `approval_token`, the server will not perform the mutation.
