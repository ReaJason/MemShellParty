import { Command } from "commander";

import { reportError, type GlobalOptions } from "../cli-context.js";
import {
  listProfiles,
  loadProfile,
  profilePath,
  profileRequests,
  profileSkeleton,
  profileTemplates,
  saveProfile,
} from "../core/site-profile.js";

interface ProfileCmdOptions extends GlobalOptions {
  site?: string;
  json?: boolean;
}

/**
 * `memparty profile` — manage site profiles for the mimic protocol.
 * Profiles are hand-written (by the operator or an AI agent); this command
 * only scaffolds, lists and inspects them.
 */
export function registerProfileCommand(program: Command): void {
  const cmd = program
    .command("profile")
    .description("Manage site profiles for the mimic protocol (init / list / show / check)");

  cmd.command("init")
    .description("Write a skeleton profile JSON for hand-authoring")
    .argument("<name>", "profile name (letters, digits, '.', '_', '-')")
    .requiredOption("--site <origin>", "site origin, e.g. http://target:8080")
    .option("--json", "output raw JSON")
    .action((name: string, opts: ProfileCmdOptions) => {
      try {
        const profile = profileSkeleton(name, opts.site!);
        saveProfile(profile);
        if (opts.json) {
          process.stdout.write(`${JSON.stringify({ ok: true, ...profile }, null, 2)}\n`);
        } else {
          process.stdout.write(
            `profile skeleton written -> ${profilePath(name)}\n` +
              `now edit it: paste a real page's HTML into "template", set "title",\n` +
              `and fill "paths" with the site's path vocabulary (e.g. ["/api/", "/news/"]).\n` +
              `AI agents: read the site's pages yourself and pick a high-traffic,\n` +
              `self-contained page — see the "Site-mimicking traffic (mimic protocol)"\n` +
              `section of the memshell-party skill.\n`,
          );
        }
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
      }
    });

  cmd.command("list")
    .description("List saved profiles")
    .option("--json", "output raw JSON")
    .action((opts: ProfileCmdOptions) => {
      const names = listProfiles();
      if (opts.json) {
        process.stdout.write(`${JSON.stringify({ profiles: names }, null, 2)}\n`);
      } else {
        process.stdout.write(names.length > 0 ? `${names.join("\n")}\n` : "(no profiles yet)\n");
      }
    });

  cmd.command("show")
    .description("Print a saved profile")
    .argument("<name>", "profile name")
    .option("--json", "output raw JSON (default)")
    .action((name: string) => {
      try {
        const profile = loadProfile(name);
        process.stdout.write(`${JSON.stringify(profile, null, 2)}\n`);
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), []);
        process.exitCode = 1;
      }
    });

  cmd.command("check")
    .description("Validate a saved profile (schema + basic sanity), exit 0 when valid")
    .argument("<name>", "profile name")
    .option("--json", "output raw JSON")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty profile check acme
  $ memparty profile check acme --json
`,
    )
    .action((name: string, opts: ProfileCmdOptions) => {
      try {
        const profile = loadProfile(name); // load validates
        if (opts.json) {
          process.stdout.write(`${JSON.stringify({ ok: true, name }, null, 2)}\n`);
        } else {
          const templates = profileTemplates(profile);
          const lines = templates.map(
            (t, i) => `  tpl[${i}]:  ${t.template.length} bytes (${t.contentType}) ${t.title || "(no title)"}`,
          );
          const shapes = profileRequests(profile)
            .map((r) => `${r.secretField}${r.secretIn && r.secretIn !== "body" ? ` (${r.secretIn})` : ""}`)
            .join(", ");
          const requestLine = shapes ? `  request:  ${shapes}\n` : "";
          process.stdout.write(
            `profile '${name}' is valid\n` +
              `  site:     ${profile.site}\n` +
              `${lines.join("\n")}\n` +
              requestLine +
              `  paths:    ${profile.paths.join("  ") || "(none — --dynamic-path will be a no-op)"}\n`,
          );
        }
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
      }
    });
}
