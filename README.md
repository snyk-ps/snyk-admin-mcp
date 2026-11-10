# Snyk Admin MCP Server

An MCP server for Snyk group admins. Every change goes through a dry run first.

## What it can do

- **Orgs:** list orgs and integrations, create orgs, copy settings (V1, Snyk Code, Open Source languages, Secrets), and clone integrations between orgs.
- **Projects:** find projects by name, tag, origin, or attributes; add or remove tags; set criticality, environment, lifecycle, test frequency, and owner; move projects between orgs.
- **People and activity:** list org and group members and their roles, and search audit logs.
- **Ignores:** list an org's Snyk Code ignore policies and copy them to another org.
- **Assets:** search, classify, label, and tag repositories, images, and packages, in both the Asset API and the Inventory API.
- **Collections:** list, create, and update project collections.

**[TOOLS.md](TOOLS.md) lists every tool, what it does, and the details that matter when you use it.**

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

## Changes: dry run, then apply

Tools that change Snyk (marked ✎ in [TOOLS.md](TOOLS.md)) work in two steps:

1. Call the tool with `dry_run: true` (the default). It returns a plan and an `approval_token`.
2. Call it again with `dry_run: false` and that token.

The token only applies the exact plan that was previewed (same tool and arguments, within 10 minutes, once). It is **not** a human sign-off: the AI receives the token and can make the apply call itself. The human check is your MCP client's confirmation prompt, so **don't "always allow" the ✎ tools**.

To help with that, every tool is labelled read-only, additive, or destructive (MCP annotations), so clients can ask before running the ones that change things.

## License

Copyright 2026 Snyk Ltd. Licensed under the [Apache License, Version 2.0](LICENSE).
