import { Command } from "commander";

import { reportError, type GlobalOptions } from "../cli-context.js";
import { MOCK_HOMEPAGE, startMimicServer } from "../connect/mimic-server.js";
import { getProtocol } from "../connect/registry.js";
import { saveProfile, type SiteProfile } from "../core/site-profile.js";
import type { ResolvedConnection } from "../core/targets.js";

interface DemoCmdOptions extends GlobalOptions {
  cmd?: string;
  json?: boolean;
}

/**
 * The profile for the demo's fake site, written by hand — in a real
 * engagement this is the file the operator (or AI agent) authors after
 * reading the target's pages.
 */
function demoProfile(site: string): SiteProfile {
  return {
    name: "demo",
    site,
    createdAt: new Date().toISOString(),
    templates: [
      {
        title: "云枢科技 - 企业数字化服务商",
        template: MOCK_HOMEPAGE,
        contentType: "text/html; charset=utf-8",
      },
    ],
    paths: ["/products/", "/news/", "/about/"],
  };
}

/**
 * `memparty demo` — run the whole mimic loop locally against a fake
 * business site: hand-written profile, handshake, then one command.
 * Nothing leaves 127.0.0.1.
 */
export function registerDemoCommand(program: Command): void {
  program
    .command("demo")
    .description(
      "Run the mimic protocol end-to-end locally: fake business site + profile " +
        "+ connect + one exec (no external traffic)",
    )
    .option("--cmd <command>", "command to execute on the fake target", "whoami")
    .option("--json", "output raw JSON")
    .addHelpText(
      "after",
      `
This is the reference walk-through for the mimic plugin:
  1. starts a fake business site on 127.0.0.1 (a mimic shell hides in it)
  2. loads a hand-written site profile (in real engagements the operator
     or AI agent writes it — see 'memparty profile init')
  3. 'connect' does a credential round-trip using a dynamic path
  4. 'exec' runs --cmd through the same channel
Watch the printed request URL in step 3/4: it changes every run.
`,
    )
    .action(async (opts: DemoCmdOptions, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOptions & { timeout?: string };
      const timeoutMs = Number.parseInt(globals.timeout ?? "30000", 10);
      const log = (line: string) => {
        if (!opts.json) process.stdout.write(`${line}\n`);
      };

      const server = await startMimicServer();
      try {
        log(`[1/4] fake business site up at ${server.url}`);

        const profile = demoProfile(server.url.replace(/\/+$/, ""));
        saveProfile(profile);
        log(
          `[2/4] profile 'demo' loaded: title=${JSON.stringify(profile.templates![0]!.title)}, ` +
            `paths=[${profile.paths.join(", ")}], templates=${profile.templates!.length}`,
        );

        const protocol = getProtocol("mimic")!;
        const conn: ResolvedConnection = {
          url: server.url,
          tool: "mimic",
          pass: "pass",
          key: "key",
          extraHeaders: {},
          profile: "demo",
        };
        const common = { timeoutMs };
        const options = { profile: "demo", dynamicPath: true };

        const test = await protocol.test({ conn, common, options });
        if (!test.ok) throw new Error(`connect failed: ${test.error}`);
        log(`[3/4] connect ok — ${test.detail}`);

        const result = await protocol.exec!({ conn, common, options }, opts.cmd!);
        if (!result.ok) throw new Error(`exec failed: ${result.error}`);
        log(`[4/4] exec ok — ${JSON.stringify(opts.cmd)} output:`);

        if (opts.json) {
          process.stdout.write(
            `${JSON.stringify({ ok: true, profile, test, exec: result }, null, 2)}\n`,
          );
        } else {
          process.stdout.write(`${result.output ?? ""}`);
          if (result.output && !result.output.endsWith("\n")) process.stdout.write("\n");
        }
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
      } finally {
        await server.close();
      }
    });
}
