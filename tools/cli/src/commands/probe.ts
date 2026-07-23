import { Command, Option } from "commander";

import { createClient, type GlobalOptions, logInfo } from "../cli-context.js";
import { logOp } from "../core/oplog.js";
import { emitPayload } from "../core/output.js";
import { buildProbeRequest, type ProbeOptions } from "../core/request-builder.js";
import { runProbeWizard } from "../wizard/probe-wizard.js";

interface ProbeCmdOptions extends GlobalOptions {
  method?: string;
  content?: string;
  packer?: string;
  jdk?: string;
  debug?: boolean;
  bypassModule?: boolean;
  shrink?: boolean;
  lambdaSuffix?: boolean;
  staticInitialize?: boolean;
  shellClassName?: string;
  host?: string;
  seconds?: string;
  sleepServer?: string;
  server?: string;
  reqParamName?: string;
  commandTemplate?: string;
  output?: string;
  decode?: boolean;
  json?: boolean;
  interactive?: boolean;
}

const REQUIRED = ["method", "content", "packer"] as const;

function toOptions(o: ProbeCmdOptions): ProbeOptions {
  return {
    probeMethod: o.method!,
    probeContent: o.content!,
    packer: o.packer!,
    jdk: o.jdk,
    debug: o.debug,
    byPassJavaModule: o.bypassModule,
    shrink: o.shrink,
    lambdaSuffix: o.lambdaSuffix,
    staticInitialize: o.staticInitialize,
    shellClassName: o.shellClassName,
    host: o.host,
    seconds: o.seconds !== undefined ? Number(o.seconds) : undefined,
    sleepServer: o.sleepServer,
    server: o.server,
    reqParamName: o.reqParamName,
    commandTemplate: o.commandTemplate,
  };
}

export function registerProbeCommand(program: Command): void {
  program
    .command("probe")
    .description("Generate a probe/detection shell. Runs an interactive wizard when required flags are missing.")
    .option("-m, --method <method>", "probe method: ResponseBody, DNSLog, Sleep")
    .option("-c, --content <content>", "probe content: BasicInfo, Server, OS, JDK, Bytecode, Command")
    .option("-p, --packer <packer>", "packer, e.g. Base64, JSP")
    .option("--jdk <version>", "target JDK: java6/8/9/11/17/21, or a class-file major version")
    .option("--debug", "enable debug output")
    .option("--bypass-module", "bypass Java module restrictions")
    .option("--no-shrink", "disable bytecode shrinking (enabled by default)")
    .option("--lambda-suffix", "append a lambda class-name suffix")
    .option("--no-static-initialize", "disable static initialization (enabled by default)")
    .option("--shell-class-name <name>", "explicit shell class name")
    .option("--host <host>", "DNSLog host (DNSLog method)")
    .option("--seconds <n>", "sleep seconds (Sleep method)")
    .option("--sleep-server <server>", "server to fingerprint (Sleep method)")
    .option("--server <server>", "server (ResponseBody method)")
    .option("--req-param-name <name>", "request param name (ResponseBody method)")
    .option("--command-template <tpl>", "command template ({command} placeholder)")
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
  $ memparty probe                                # interactive wizard
  $ memparty probe -m ResponseBody -c Command -p DefaultBase64 \\
      --server Tomcat --req-param-name cmd
  $ memparty probe -m DNSLog -c Server -p DefaultBase64 --host x.dnslog.cn
  $ memparty probe -m Sleep -c Server -p DefaultBase64 \\
      --sleep-server Tomcat --seconds 5

Note: a probe is a detection shell that reports what the target supports.
The server name reported by '-c Server' is the value to pass as
'memparty gen -s'.
`,
    )
    .action(async (opts: ProbeCmdOptions, cmd: Command) => {
      const client = createClient(cmd.optsWithGlobals());

      const missing = REQUIRED.filter((k) => !opts[k]);
      const stdinIsTty = Boolean(process.stdin.isTTY);
      const wantWizard =
        opts.interactive === true ||
        (opts.interactive !== false && missing.length > 0 && stdinIsTty);

      let probeOpts: ProbeOptions;
      if (wantWizard) {
        probeOpts = await runProbeWizard(client);
      } else {
        if (missing.length > 0) {
          throw new Error(
            `Missing required option(s): ${missing.map((m) => `--${m}`).join(", ")}. ` +
              `Run in a terminal for the wizard, or pass -i.`,
          );
        }
        probeOpts = toOptions(opts);
      }

      const request = buildProbeRequest(probeOpts);
      const probeMeta = {
        probeMethod: probeOpts.probeMethod,
        probeContent: probeOpts.probeContent,
        packer: probeOpts.packer,
        jdk: probeOpts.jdk,
      };
      const started = Date.now();
      let response;
      try {
        response = await client.generateProbe(request);
      } catch (err) {
        logOp({
          category: "probe",
          action: "probe",
          ok: false,
          durationMs: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
          meta: probeMeta,
        });
        throw err;
      }
      logOp({
        category: "probe",
        action: "probe",
        ok: true,
        durationMs: Date.now() - started,
        detail: `${response.probeShellResult.shellClassName} (${response.probeShellResult.shellSize} bytes)`,
        meta: probeMeta,
      });

      if (opts.json) {
        process.stdout.write(`${JSON.stringify(response, null, 2)}\n`);
        return;
      }

      const r = response.probeShellResult;
      logInfo(`shell class: ${r.shellClassName} (${r.shellSize} bytes)`);

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
