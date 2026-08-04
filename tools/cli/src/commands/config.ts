import { Command } from "commander";

import { createClient, type GlobalOptions } from "../cli-context.js";

interface ConfigCmdOptions extends GlobalOptions {
  json?: boolean;
}

function printJsonOrLines(data: unknown, json: boolean | undefined, renderLines: () => string[]): void {
  if (json) {
    process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
  } else {
    process.stdout.write(`${renderLines().join("\n")}\n`);
  }
}

export function registerConfigCommand(program: Command): void {
  const config = program
    .command("config")
    .description("Query supported servers, shell tools, shell types, and packers")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty config servers          # servers + their shell types (values for gen -s)
  $ memparty config tools Tomcat     # tools available on one server (values for gen -t)
  $ memparty config packers          # packer tree (values for gen -p)
  $ memparty config command          # Command-tool encryptors and impl classes
`,
    );

  config
    .command("servers")
    .description("List supported servers and their shell types")
    .option("--json", "output raw JSON")
    .action(async (opts: ConfigCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());
      const servers = await client.getServers();
      printJsonOrLines(servers, opts.json, () =>
        Object.entries(servers).map(([name, types]) => `${name}\n  ${types.join(", ")}`),
      );
    });

  config
    .command("tools")
    .description("List shell tools (and their shell types) per server")
    .argument("[server]", "filter by a single server name")
    .option("--json", "output raw JSON")
    .action(async (server: string | undefined, opts: ConfigCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());
      const config = await client.getConfig();
      const filtered = server ? { [server]: config[server] ?? {} } : config;
      printJsonOrLines(filtered, opts.json, () =>
        Object.entries(filtered).flatMap(([name, tools]) => [
          name,
          ...Object.entries(tools).map(([tool, types]) => `  ${tool}: ${types.join(", ")}`),
        ]),
      );
    });

  config
    .command("packers")
    .description("List packers (parent / child tree)")
    .option("--json", "output raw JSON")
    .action(async (opts: ConfigCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());
      const tree = await client.getPackerTree();
      printJsonOrLines(tree, opts.json, () =>
        tree.map((p) => (p.children.length ? `${p.name}\n  ${p.children.join(", ")}` : p.name)),
      );
    });

  config
    .command("command")
    .description("List Command-tool encryptors and implementation classes")
    .option("--json", "output raw JSON")
    .action(async (opts: ConfigCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());
      const cc = await client.getCommandConfigs();
      printJsonOrLines(cc, opts.json, () => [
        `encryptors: ${cc.encryptors.join(", ")}`,
        `implementationClasses: ${cc.implementationClasses.join(", ")}`,
      ]);
    });
}
