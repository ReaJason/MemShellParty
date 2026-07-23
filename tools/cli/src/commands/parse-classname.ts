import { readFileSync } from "node:fs";

import { Command } from "commander";

import { createClient, type GlobalOptions } from "../cli-context.js";

interface ParseCmdOptions extends GlobalOptions {
  file?: string;
}

export function registerParseClassNameCommand(program: Command): void {
  program
    .command("parse-classname")
    .description("Parse the fully-qualified class name from a .class file")
    .argument("[base64]", "base64-encoded .class bytes (omit when using --file)")
    .option("-f, --file <path>", "read a .class file from disk instead of passing base64")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty parse-classname -f shell.class
  $ memparty parse-classname "$(memparty gen -s Tomcat -t Command -y Filter \\
      -p DefaultBase64 --command-param-name cmd)"
`,
    )
    .action(async (base64: string | undefined, opts: ParseCmdOptions, cmd: Command) => {
      let classBase64: string;
      if (opts.file) {
        classBase64 = readFileSync(opts.file).toString("base64");
      } else if (base64) {
        classBase64 = base64.trim();
      } else {
        throw new Error("Provide base64 bytes as an argument or use --file <path>.");
      }

      const client = createClient(cmd.optsWithGlobals());
      const name = await client.parseClassName(classBase64);
      process.stdout.write(`${name}\n`);
    });
}
