# Snyk Admin MCP Server

MCP server for managing the Snyk platform as a customer with group admin permissions.

## Features

- **Copy settings between organizations** – Copy org settings from a source org to a target.
- **Clone integration** – Clone an integration (with settings and credentials) from one org to another.
- **Create organization** – Create a new org, optionally copying settings from a template org.
- **Project tags** – Add or remove tags on many projects in one go.
- **Asset labeling** – Search, look up, and label assets (class/labels/tags) — one at a time, or many at once. Covers repository, image, and package assets.
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
| `snyk_update_assets` | Update class, labels, and/or tags on one or more assets (repos included). One request per asset. Dry run / approval flow. |

## Notes

- **Asset labels vs. tags** – an asset's `labels` are a flat list of strings; its `tags` are key/value pairs. `snyk_update_assets` takes `add`/`remove` for both, so existing values are preserved unless you remove them explicitly.
- **The API cannot tell you where a label came from** – the Asset API documents `labels` as "unstructured, simple text strings", and the response carries no per-label provenance: a label you typed, one applied by an asset policy, and one Snyk generated are byte-identical in the payload. The Snyk UI distinguishes them; the API does not. The only reliable signal is that Snyk mirrors every detected language into `labels`, so:

  ```
  language labels = labels ∩ keys(languages)
  everything else = your labels (manual or asset-policy) + any Snyk-internal labels
  ```

  Verified across a 29-repository group: every `languages` key appeared in `labels`, with no exceptions. Two caveats on the remainder. Labels applied by an **asset policy** (Policies → Assets) are custom labels and show as such in the UI — for example an `archived` label set by a policy, which does *not* track the separate `archived` boolean attribute. And the API can return **internal labels the UI never displays**: `new repository` shows up in `labels` on recently-created repos but is not a label in the UI, so treat unexpected values as suspect rather than assuming they are yours. If you need true provenance, list the group's asset policies (`GET /groups/{group_id}/policies`) and match on the label values their actions apply; note that disabling such a policy removes its labels from the matched assets.
- **Project tags are not asset labels** – `snyk_add_project_tags` / `snyk_remove_project_tags` operate on Snyk *projects* via the V1 API. To label an asset (a repo, image, or package), use `snyk_update_assets`.
- **There is no batch asset endpoint** – `snyk_update_assets` accepts a list of `asset_ids`, but the Asset API only updates one asset per call, so the server issues one PATCH per asset (concurrently, within the rate limit) and reports per-asset success/failure. It is not atomic: a partial failure leaves earlier assets updated. The same applies to the project tag tools, which make one V1 call per project × tag.
- **`snyk_copy_org_settings` is narrow** – only fields editable through `PUT /v1/org/{orgId}/settings` are copied (for example `requestAccess`). Integrations, SCM tokens, and SSO are not affected; use `snyk_clone_integration` for integrations.
- **CLI integrations cannot be cloned** – `snyk_clone_integration` rejects them; exclude the CLI integration when copying integrations between orgs.
- **Asset tools are group-scoped** – pass a `group_id` (a group UUID), not an org ID. `snyk_list_orgs` returns each org's `group_id`.
- **Rate limits** – requests are throttled to ~90% of Snyk's published limits (REST 1620/min, V1 2000/min) with automatic retry on 429.

## Workflow (mutations)

1. Call the tool with **`dry_run: true`** (default).
2. Review the returned plan and **`approval_token`**.
3. To apply, call the same tool with **`dry_run: false`** and **`approval_token`** set to that value.

Without a valid `approval_token`, the server will not perform the mutation.
