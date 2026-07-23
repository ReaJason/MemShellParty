import { Command } from "commander";

import { createClient, type GlobalOptions } from "../cli-context.js";
import { CLI_VERSION } from "../version.js";

interface VersionCmdOptions extends GlobalOptions {
  json?: boolean;
}

export function registerVersionCommand(program: Command): void {
  program
    .command("version")
    .description("Show CLI version and the backend server version")
    .option("--json", "output raw JSON")
    .action(async (opts: VersionCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());
      let server: Awaited<ReturnType<typeof client.getVersion>> | { error: string };
      try {
        server = await client.getVersion();
      } catch (err) {
        server = { error: (err as Error).message };
      }

      if (opts.json) {
        process.stdout.write(`${JSON.stringify({ cli: CLI_VERSION, server }, null, 2)}\n`);
        return;
      }

      const lines = [`CLI:    ${CLI_VERSION}`];
      if ("error" in server) {
        lines.push(`Server: (unavailable) ${server.error}`);
      } else {
        lines.push(`Server: ${server.currentVersion}`);
        if (server.hasUpdate) {
          lines.push(`Update: ${server.latestVersion} available`);
        }
      }
      process.stdout.write(`${lines.join("\n")}\n`);
    });
}
