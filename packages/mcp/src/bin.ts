#!/usr/bin/env node
/** Executable entry — `greenteamgo-mcp`. The library surface (importable
 * without side effects) is ./index.ts. */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { buildServer } from "./server.js";

async function main(): Promise<void> {
  const cfg = loadConfig();
  const server = buildServer(cfg);
  await server.connect(new StdioServerTransport());
  // stdout is the MCP transport; log to stderr only.
  console.error(`greenteamgo-mcp connected (api: ${cfg.apiUrl})`);
}

main().catch((err) => {
  console.error("greenteamgo-mcp fatal:", err instanceof Error ? err.message : err);
  process.exit(1);
});
