# Snyk Admin MCP Server

An MCP server for Snyk group admins. Every change goes through a dry run first.

## What it can do

- **Orgs:** list orgs and integrations, create orgs, copy settings (V1, notifications, Snyk Code, Open Source languages, Secrets, IaC), clone integrations between orgs, and review or set integrations' pull request check settings across many orgs.
- **Projects:** find projects by name, tag, origin, or attributes; add or remove tags; set criticality, environment, lifecycle, test frequency, and owner; review pull request check settings; move projects between orgs.
- **People and activity:** list org and group members and their roles, see everywhere one person has access in a group, list invites that haven't been accepted, and search audit logs. These are read-only: the server can't add, change, or remove anyone's access.
- **Ignores:** list an org's Snyk Code ignore policies and copy them to another org.
- **Security checks:** list service accounts (without their credentials), installed Snyk Apps, and Broker connections.
- **Assets:** search, classify, label, and tag repositories, images, and packages, in both the Asset API and the Inventory API.
- **Collections:** list, create, and update project collections.

**[TOOLS.md](TOOLS.md) lists every tool, what it does, and the details that matter when you use it.**

## Install

You need a Snyk API token (or a service account key) with admin access to the orgs or group you'll manage, and your region:

| Region | Snyk web app | Tenant |
|--------|--------------|--------|
| `us-01` (default) | `app.snyk.io` | SNYK-US-01 |
| `us-02` | `app.us.snyk.io` | SNYK-US-02 |
| `eu-01` | `app.eu.snyk.io` | SNYK-EU-01 |
| `au-01` | `app.au.snyk.io` | SNYK-AU-01 |

See [Snyk regions](https://docs.snyk.io/snyk-data-and-governance/regional-hosting-and-data-residency) if you're not sure which one you're on.

### Claude Desktop: install the bundle

1. Download `snyk-admin-mcp-<version>.mcpb` from the [latest release](https://github.com/snyk-ps/snyk-admin-mcp/releases/latest).
2. Double-click it, or drag it into Claude Desktop, or use **Settings > Extensions > Advanced settings > Install Extension…**.
3. Enter your Snyk API token, and your region if it isn't `us-01`. Claude Desktop stores the token securely.

Nothing else to install: Claude Desktop includes Node.js. To update, install the newer bundle the same way.

### Other MCP clients: run from GitHub with npx

Needs Node.js 22+ and git. Add this to your client's MCP config (Claude Code, Cursor, Windsurf, …):

```json
{
  "mcpServers": {
    "snyk-admin": {
      "command": "npx",
      "args": ["-y", "github:snyk-ps/snyk-admin-mcp"],
      "env": { "SNYK_API_TOKEN": "your-token", "SNYK_API_REGION": "us-01" }
    }
  }
}
```

- To pin a release, use `github:snyk-ps/snyk-admin-mcp#vX.Y.Z`.
- The first start downloads and builds the server, which can take a minute. Run `npx -y github:snyk-ps/snyk-admin-mcp --version` once in a terminal first, so your client doesn't time out waiting.
- Some clients use a different shape; VS Code, for example, uses a `servers` key with `"type": "stdio"`. On Windows, some clients need `"command": "cmd"` with `"args": ["/c", "npx", "-y", "github:snyk-ps/snyk-admin-mcp"]`.

### From source

Needs Node.js 22+.

```bash
git clone https://github.com/snyk-ps/snyk-admin-mcp.git
cd snyk-admin-mcp
npm install    # also builds dist/
```

Set `SNYK_API_TOKEN` (or `SNYK_TOKEN`) and `SNYK_API_REGION` in your MCP client's config, or in a `.env` file in the project root (it's gitignored), and point the client at the built server:

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

To build the Claude Desktop bundle, run `npm run bundle`. It writes `build/snyk-admin-mcp-<version>.mcpb`, ready to attach to a release.

## Changes: dry run, then apply

Tools that change Snyk (marked ✎ in [TOOLS.md](TOOLS.md)) work in two steps:

1. Call the tool with `dry_run: true` (the default). It returns a plan and an `approval_token`.
2. Call it again with `dry_run: false` and that token.

The token only applies the exact plan that was previewed (same tool and arguments, within 10 minutes, once). On its own it is **not** a human sign-off: the AI receives the token and can make the apply call itself. Two things put a person in the loop:

- **A confirmation prompt.** If your MCP client supports elicitation, the server shows you the plan and asks you to confirm before every apply. Nothing changes unless you tick **Apply this change** and submit; declining cancels the plan. To turn the prompt off (for a client that advertises elicitation but can't show it), set `SNYK_ADMIN_CONFIRM=off` in the server's environment.
- **Your client's tool permissions.** Every tool is labelled read-only, additive, or destructive (MCP annotations), so clients can ask before running the ones that change things. **Don't "always allow" the ✎ tools**, especially in a client without elicitation.

## License

Copyright 2026 Snyk Ltd. Licensed under the [Apache License, Version 2.0](LICENSE).
