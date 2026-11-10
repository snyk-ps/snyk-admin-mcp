// Build an MCP bundle (.mcpb) for Claude Desktop: `npm run bundle` (which builds dist/ first).
// Output: build/snyk-admin-mcp-<version>.mcpb, to attach to a GitHub release.
// `--stage-only` prepares build/mcpb/ (what goes in the bundle) without running the MCPB CLI.
//
// The bundle holds dist/, the production dependencies only, and manifest.json with its version
// taken from package.json and its tool list taken from the server's own registry, so neither
// can drift. The MCPB CLI is fetched with npx only when this runs, rather than being a
// devDependency: its own dependencies carry npm audit findings, and devDependencies are installed
// on every machine that runs this server from GitHub with npx.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const MCPB_CLI = "@anthropic-ai/mcpb@2.1.2";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const build = path.join(root, "build");
const stage = path.join(build, "mcpb");
const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));

rmSync(build, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
for (const f of ["dist", "LICENSE", "README.md", "TOOLS.md", "package.json", "package-lock.json"]) {
  cpSync(path.join(root, f), path.join(stage, f), { recursive: true });
}

/** The first sentence of a tool description, for the install screen's tool list. */
const firstSentence = (s) => (s.match(/^.*?[.!?](?=\s+[A-Z(]|$)/s)?.[0] ?? s).trim();
const manifest = JSON.parse(readFileSync(path.join(root, "manifest.json"), "utf8"));
manifest.version = pkg.version;
const { listTools } = await import(pathToFileURL(path.join(root, "dist", "tools", "index.js")).href);
manifest.tools = listTools().map((t) => ({ name: t.name, description: firstSentence(t.description) }));
writeFileSync(path.join(stage, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

// Production dependencies only. --ignore-scripts: `prepare` runs tsc, which isn't installed here
// (and dist/ is already built).
const run = (cmd, args, cwd = root) => execFileSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
run("npm", ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], stage);

if (process.argv.includes("--stage-only")) {
  console.log(`\nStaged (not packed): ${stage}`);
  process.exit(0);
}
const out = path.join(build, `snyk-admin-mcp-${pkg.version}.mcpb`);
run("npx", ["-y", MCPB_CLI, "validate", path.join(stage, "manifest.json")]);
run("npx", ["-y", MCPB_CLI, "pack", stage, out]);
console.log(`\nBundle: ${out}`);
