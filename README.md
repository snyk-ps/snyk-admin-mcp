# Snyk Admin MCP Server

MCP server for managing the Snyk platform as a customer with group admin permissions.

## Features

- **Copy settings between organizations** – Copy org settings from a source org to a target.
- **Clone integration** – Clone an integration (with settings and credentials) from one org to another.
- **Create organization** – Create a new org, optionally copying settings from a template org.
- **Project tags** – Add or remove tags on many projects in one go.
- **Asset labeling** – Search, look up, and label assets (class/labels/tags) — one at a time, or many at once.
- **Dry run + approval** – Every mutation supports `dry_run=true` (default) to preview a plan first. Apply with `dry_run=false` and the `approval_token` returned from the dry run. Tokens expire after 10 minutes.

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
  "SNYK_API_REGION": "global"
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
| `snyk_create_organization` | Create a new Snyk organization. Optional: `group_id`, `source_org_id` (copy settings from a template org). Dry run / approval flow. |
| `snyk_copy_org_settings` | Copy org settings from a source org to a target org. Dry run → plan + `approval_token`; then call again with `dry_run=false` and that token to apply. |
| `snyk_clone_integration` | Clone one integration from a source org to a target org (CLI integrations excluded). Same dry run / approval flow. |
| `snyk_add_project_tags` | Add tags to multiple projects at once. Same dry run / approval flow. |
| `snyk_remove_project_tags` | Remove tags (by key) from multiple projects at once. Same dry run / approval flow. |
| `snyk_search_assets` | Search assets in a group with optional attribute filters. Read-only. |
| `snyk_get_asset` | Get a single asset by ID within a group. Read-only. |
| `snyk_list_asset_projects` | List projects related to an asset, with cursor pagination. Read-only. |
| `snyk_list_related_assets` | List assets related to an asset, with optional type filter and pagination. Read-only. |
| `snyk_update_asset` | Update one asset's class, labels, and/or tags. Dry run / approval flow. |
| `snyk_bulk_update_inventory_assets` | Update class/labels/tags for many assets in a single request. Dry run / approval flow. |

## Workflow (mutations)

1. Call the tool with **`dry_run: true`** (default).
2. Review the returned plan and **`approval_token`**.
3. To apply, call the same tool with **`dry_run: false`** and **`approval_token`** set to that value.

Without a valid `approval_token`, the server will not perform the mutation.
