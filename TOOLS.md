# Tools

Every tool the Snyk Admin MCP server provides, grouped by the section of the [Snyk API reference](https://docs.snyk.io/developer-tools/snyk-api/reference) whose endpoints it calls, in the reference's order. Tools are listed alphabetically within each section. For setup, see the [README](README.md).

✎ = changes Snyk. These tools preview a plan first and only apply it with the approval token from that preview; see [Changes: dry run, then apply](README.md#changes-dry-run-then-apply).

## General

- Every tool is labelled for MCP clients: read-only for the `list`, `get`, and `search` tools; additive for `snyk_create_organization`, `snyk_create_collection`, and `snyk_add_project_tags`; destructive for the other ✎ tools.
- Requests are throttled to about 90% of Snyk's rate limits and retried on 429.
- Bulk changes aren't atomic: if one item fails, earlier items stay changed. Results list each item or batch.
- Group-scoped tools take a `group_id`; `snyk_list_orgs` shows each org's.
- Page sizes for orgs, projects, members, and collections are 10–100 in steps of 10 (Snyk's rule); for assets, any 10–100.
- Copy, move, and clone refuse the same org as source and target.
- **The Asset and Inventory Assets APIs are separate stores.** IDs differ (Asset: 32 hex characters; Inventory: dashed UUIDs), and neither API accepts the other's. Labels and tags are separate too: a label set in one doesn't show in the other.

## [Asset](https://docs.snyk.io/developer-tools/snyk-api/reference/asset)

Early Access. Group scope; repositories, images, packages.

| Tool | What it does |
|------|--------------|
| `snyk_get_asset` | Get every attribute of one asset. |
| `snyk_list_asset_projects` | List an asset's projects. |
| `snyk_list_related_assets` | List an asset's related assets, e.g. the images built from a repository. |
| `snyk_search_assets` | Search assets with attribute filters; one line per asset with class, labels, issues, and coverage gaps. |
| `snyk_update_assets` ✎ | Set class, add or remove labels and tags (one request per asset; the dry run checks each ID and type). |

- Use these tools for packages and for an asset's related projects or assets. Their IDs don't work with the Inventory Assets tools.
- Labels are plain strings; tags are key/value pairs. Snyk copies each detected language into an asset's labels, so labels matching its languages are automatic.

## [Audit Logs](https://docs.snyk.io/developer-tools/snyk-api/reference/audit-logs)

| Tool | What it does |
|------|--------------|
| `snyk_search_audit_logs` | Search org or group audit logs by time, user, project, event; one line per entry. |

- 20 entries per page by default (up to 100). Each entry's details, such as a setting's before and after values, are left out unless `include_content` is true.
- Leaves out `api.access` events unless you ask for them in `events`.

## [Collection](https://docs.snyk.io/developer-tools/snyk-api/reference/collection)

Org scope.

| Tool | What it does |
|------|--------------|
| `snyk_create_collection` ✎ | Create a collection, optionally with projects. |
| `snyk_list_collection_projects` | List a collection's projects. |
| `snyk_list_collections` | List an org's collections with project and issue counts. |
| `snyk_update_collection` ✎ | Rename a collection; add or remove projects. |

- There is no group-level endpoint; covering a group means one call per org. A collection's projects must be in its org.
- Snyk generates one collection per imported repo (`is_generated`); filter with `is_generated: false` to see only people-made ones.
- The API silently ignores unknown project IDs and projects from other orgs, so the tools re-read the collection after a change and report `not_added` / `not_removed`.
- Collection project lists have IDs and issue counts but no names; use `snyk_list_projects` for names. A collection ID that doesn't exist is an error, not an empty list.

## [Integrations (v1)](https://docs.snyk.io/developer-tools/snyk-api/reference/integrations-v1)

| Tool | What it does |
|------|--------------|
| `snyk_clone_integration` ✎ | Clone an integration, with credentials, to another org (not CLI). |
| `snyk_list_integrations` | List an org's integrations. |

- If the target org already has an integration of that type, the clone writes into it, replacing its settings and credentials, rather than adding a second one. The dry run warns when that will happen.

## [Inventory Assets](https://docs.snyk.io/developer-tools/snyk-api/reference/inventory-assets)

Early Access. Org or group scope; repositories, images, SBOMs.

| Tool | What it does |
|------|--------------|
| `snyk_get_inventory_asset_counts` | Count assets by one field, e.g. `visibility` or `class`. |
| `snyk_list_inventory_assets` | List or filter assets (RSQL), with the total count. |
| `snyk_list_inventory_fields` | Fields you can filter or group by, or suggested values for one. |
| `snyk_update_inventory_assets` ✎ | Set class, add or remove labels and tags, 100 assets per request. |

- Use these tools for org scope, RSQL filters, counts, and labelling many assets in fewer requests. Their IDs don't work with the Asset tools; `snyk_update_inventory_assets` rejects Asset IDs, naming the tool that takes them.
- Updates are all-or-nothing per 100-asset request. The dry run checks every ID exists first, and the tool only adds or removes labels and tags, never replaces them all.

## [Organizations (v1)](https://docs.snyk.io/developer-tools/snyk-api/reference/organizations-v1)

| Tool | What it does |
|------|--------------|
| `snyk_copy_org_settings` ✎ | Copy V1, SAST, Open Source language, and Secrets settings to another org. |
| `snyk_create_organization` ✎ | Create an org, optionally copying settings from a template org. |

- The `snyk_copy_org_settings` dry run shows the target's Snyk Code and Snyk Secrets state before and after, and warns if the copy would turn either one off.
- `snyk_copy_org_settings` also uses the [SastSettings](https://docs.snyk.io/developer-tools/snyk-api/reference/sastsettings), [LanguagesSettings](https://docs.snyk.io/developer-tools/snyk-api/reference/languagessettings), and [SecretsSettings](https://docs.snyk.io/developer-tools/snyk-api/reference/secretssettings) APIs. It applies the four parts separately and reports each one. For V1 settings it copies only the fields the API lets you edit (e.g. `requestAccess`). If the source org's Secrets settings can't be read (usually because it has no Snyk Secrets), that part is skipped.

## [Orgs](https://docs.snyk.io/developer-tools/snyk-api/reference/orgs)

| Tool | What it does |
|------|--------------|
| `snyk_list_members` | List an org's or group's members and roles; filter by email, username, or role. |
| `snyk_list_orgs` | List orgs; filter by group, name, slug, personal. |

- `snyk_list_members` with `group_id` uses the [Groups](https://docs.snyk.io/developer-tools/snyk-api/reference/groups) memberships endpoint. It lists group-level memberships (such as Group Admin), not each org's members.

## [Policies](https://docs.snyk.io/developer-tools/snyk-api/reference/policies)

Snyk Code consistent ignores. Org scope; the org needs "Ignores across the repository for Snyk Code" turned on.

| Tool | What it does |
|------|--------------|
| `snyk_copy_ignore_policies` ✎ | Copy an org's ignore policies to another org, all in effect or chosen ones. |
| `snyk_list_ignore_policies` | List an org's ignore policies: type, expiry, review state, the finding each ignores, who and why. |

- Each policy ignores one Snyk Code finding across a repository, matched by the finding's repository-level ID, so a copy only hides that finding where the target org scans the same repository.
- The copy skips rejected and expired policies, pending ones unless `include_pending`, and findings the target org already has an active or pending policy for (an expired or rejected one there doesn't count). With `include_pending`, the dry run warns that those policies may take effect in the target straight away. It's labelled destructive because ignores hide findings.
- Copied policies are created as the API token's user; the target org's ignore approval settings may put them in review. Retest the target's Snyk Code projects for them to show.

## [Projects (v1)](https://docs.snyk.io/developer-tools/snyk-api/reference/projects-v1)

| Tool | What it does |
|------|--------------|
| `snyk_add_project_tags` ✎ | Add tags to many projects. |
| `snyk_move_projects` ✎ | Move projects to another org. |
| `snyk_remove_project_tags` ✎ | Remove tags, by key, from many projects. |

- The dry runs check every project ID is in the org first, and stop if one isn't.
- Project tags are not asset labels.
- `snyk_move_projects` needs group admin. Moving across groups needs a personal API key, not a service account key.

## [Projects](https://docs.snyk.io/developer-tools/snyk-api/reference/projects)

| Tool | What it does |
|------|--------------|
| `snyk_list_projects` | List an org's projects, 100 per page; filter by name or prefix, tags, origin, type, branch, or attributes; or just count them. |
| `snyk_update_projects` ✎ | Set business criticality, environment, lifecycle, test frequency, or owner on many projects. |

- `snyk_update_projects` replaces each attribute list you pass (`[]` clears it) and keeps the ones you leave out. It doesn't change tags; use the tag tools. Owners are user IDs from `snyk_list_members`. The dry run checks every project ID is in the org first.
