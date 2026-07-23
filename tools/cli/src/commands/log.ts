import { Command, Option } from "commander";

import { formatOp, opLogPath, readOps, type OpCategory } from "../core/oplog.js";

interface LogCmdOptions {
  category?: OpCategory;
  target?: string;
  limit?: string;
  json?: boolean;
}

export function registerLogCommand(program: Command): void {
  program
    .command("log")
    .description("Show the global operation log")
    .addOption(
      new Option("--category <name>", "filter by operation category").choices([
        "gen",
        "probe",
        "connect",
        "exec",
        "download",
        "upload",
        "save",
        "note",
        "remove",
      ]),
    )
    .option(
      "--target <name>",
      "filter by target: project name, project/shell, or a URL substring (e.g. host)",
    )
    .option("--limit <n>", "max entries (default 50)", "50")
    .option("--json", "output raw JSON entries (newest first)")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty log                          # latest 50 operations
  $ memparty log --category exec          # only command executions
  $ memparty log --category save          # only target saves
  $ memparty log --target web1           # everything against project web1
  $ memparty log --category exec --target 192.0.2.10 --json
`,
    )
    .action((opts: LogCmdOptions) => {
      const limit = Number.parseInt(opts.limit ?? "50", 10);
      const entries = readOps({
        category: opts.category,
        target: opts.target,
        limit: Number.isNaN(limit) ? 50 : limit,
      });
      if (opts.json) {
        process.stdout.write(`${JSON.stringify({ logPath: opLogPath(), entries }, null, 2)}\n`);
        return;
      }
      if (entries.length === 0) {
        process.stdout.write(`no operations logged yet (log: ${opLogPath()})\n`);
        return;
      }
      for (const entry of entries) {
        process.stdout.write(`${formatOp(entry)}\n`);
      }
    });
}
