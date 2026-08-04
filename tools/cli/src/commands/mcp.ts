import { Command } from "commander";

import { createClient, type GlobalOptions, logInfo } from "../cli-context.js";
import { startMcpStdio } from "../mcp/server.js";
import { resolveApiUrl } from "../core/config.js";

export function registerMcpCommand(program: Command): void {
  program
    .command("mcp")
    .description("Run as an MCP server over stdio (exposes generation + config tools)")
    .action(async (_opts: GlobalOptions, cmd: Command) => {
      const globals = cmd.optsWithGlobals();
      const client = createClient(globals);
      logInfo(`memshell-party MCP server starting (api: ${resolveApiUrl({ flag: globals.api })})`);
      await startMcpStdio(client);
    });
}
