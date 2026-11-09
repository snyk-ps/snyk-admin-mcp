# Tools

Every tool the Snyk Admin MCP server provides, by area, with the details that matter when you use it. For setup, see the [README](README.md).

✎ = changes Snyk. These tools preview a plan first and only apply it with the approval token from that preview; see [Changes: dry run, then apply](README.md#changes-dry-run-then-apply).

## General

- Every tool is labelled for MCP clients: read-only for the `list`, `get`, and `search` tools; additive for `snyk_create_organization`, `snyk_create_collection`, and `snyk_add_project_tags`; destructive for the other ✎ tools.
- Requests are throttled to about 90% of Snyk's rate limits and retried on 429.
- Bulk changes aren't atomic: if one item fails, earlier items stay changed. Results list each item or batch.
- Group-scoped tools take a `group_id`; `snyk_list_orgs` shows each org's.
- Page sizes for orgs, projects, members, and collections are 10–100 in steps of 10 (Snyk's rule); for assets, any 10–100.

## Orgs and integrations

| Tool | What it does |
|------|--------------|
| `snyk_list_orgs` | List orgs; filter by group, name, slug, personal. |
| `snyk_list_integrations` | List an org's integrations. |
| `snyk_create_organization` ✎ | Create an org, optionally copying settings from a template org. |
| `snyk_copy_org_settings` ✎ | Copy V1, SAST, Open Source language, and Secrets settings to another org. |
| `snyk_clone_integration` ✎ | Clone an integration, with credentials, to another org (not CLI). |

- `snyk_copy_org_settings` applies its four parts separately and reports each one. For V1 settings it copies only the fields the API lets you edit (e.g. `requestAccess`). If the source org's Secrets settings can't be read (usually because it has no Snyk Secrets), that part is skipped.
- Copy, move, and clone refuse the same org as source and target.

## Projects

| Tool | What it does |
|------|--------------|
| `snyk_list_projects` | List an org's projects, 100 per page; filter by name or prefix, tags, origin, type, branch, or attributes; or just count them. |
| `snyk_add_project_tags` ✎ / `snyk_remove_project_tags` ✎ | Add or remove tags on many projects. |
| `snyk_update_projects` ✎ | Set business criticality, environment, lifecycle, test frequency, or owner on many projects. |
| `snyk_move_projects` ✎ | Move projects to another org. |

- The tag, update, and move dry runs check every project ID is in the org first, and stop if one isn't.
- `snyk_update_projects` replaces each attribute list you pass (`[]` clears it) and keeps the ones you leave out. It doesn't change tags; use the tag tools. Owners are user IDs from `snyk_list_members`.
- Project tags are not asset labels.
- `snyk_move_projects` needs group admin. Moving across groups needs a personal API key, not a service account key.

## Members and audit logs

| Tool | What it does |
|------|--------------|
| `snyk_list_members` | List an org's or group's members and roles; filter by email, username, or role. |
| `snyk_search_audit_logs` | Search org or group audit logs by time, user, project, event. |

- `snyk_list_members` with `group_id` lists group-level memberships (such as Group Admin), not each org's members.
- Audit log search leaves out `api.access` events unless you ask for them in `events`.

## Assets

Snyk has two asset APIs, and this server covers both. **They are separate stores.** IDs differ (Asset API: 32 hex characters; Inventory: dashed UUIDs), and neither API accepts the other's. Labels and tags are separate too: a label set in one doesn't show in the other.

- Use the Asset API tools for packages and an asset's related projects or assets.
- Use the Inventory tools for org scope, RSQL filters, counts, and labelling many assets in fewer requests.
- Labels are plain strings; tags are key/value pairs. Snyk copies each detected language into an asset's labels, so labels matching its languages are automatic.

### Asset API

Group scope; repositories, images, packages.

| Tool | What it does |
|------|--------------|
| `snyk_search_assets` | Search assets with attribute filters; one line per asset with class, labels, issues, and coverage gaps. |
| `snyk_get_asset` | Get every attribute of one asset. |
| `snyk_list_asset_projects` / `snyk_list_related_assets` | An asset's projects or related assets. |
| `snyk_update_assets` ✎ | Set class, add or remove labels and tags (one request per asset; the dry run checks each ID and type). |

### Inventory API

Early Access; org or group scope; repositories, images, SBOMs.

| Tool | What it does |
|------|--------------|
| `snyk_list_inventory_assets` | List or filter assets (RSQL), with the total count. |
| `snyk_get_inventory_asset_counts` | Count assets by one field, e.g. `visibility` or `class`. |
| `snyk_list_inventory_fields` | Fields you can filter or group by, or suggested values for one. |
| `snyk_update_inventory_assets` ✎ | Set class, add or remove labels and tags, 100 assets per request. |

- Updates are all-or-nothing per 100-asset request. The dry run checks every ID exists first, and the tool only adds or removes labels and tags, never replaces them all.
- `snyk_update_inventory_assets` rejects Asset API IDs, naming the tool that takes them.

## Collections

Org scope.

| Tool | What it does |
|------|--------------|
| `snyk_list_collections` | List collections with project and issue counts. |
| `snyk_list_collection_projects` | List a collection's projects. |
| `snyk_create_collection` ✎ | Create a collection, optionally with projects. |
| `snyk_update_collection` ✎ | Rename a collection; add or remove projects. |

- There is no group-level endpoint; covering a group means one call per org. Projects must be in the collection's org.
- Snyk generates one collection per imported repo (`is_generated`); filter with `is_generated: false` to see only people-made ones.
- The API silently ignores unknown project IDs and projects from other orgs, so the tools re-read the collection after a change and report `not_added` / `not_removed`.
- Collection project lists have IDs and issue counts but no names; use `snyk_list_projects` for names.
