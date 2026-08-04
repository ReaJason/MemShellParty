import { Command } from "commander";

import { logInfo, reportError, type GlobalOptions } from "../cli-context.js";
import { logOp } from "../core/oplog.js";
import { installSkill, type SkillScope } from "../core/skill-install.js";

interface SkillInstallCmdOptions extends GlobalOptions {
  user?: boolean;
  claude?: boolean;
  project?: string | boolean;
  json?: boolean;
}

/**
 * `memparty skill install` — copy the bundled agent skill into an agent's
 * skill directory so the mimic/memshell workflow shows up in its skill list.
 */
export function registerSkillCommand(program: Command): void {
  program
    .command("skill")
    .description("Manage the bundled agent skill (skills/memshell-party)")
    .addCommand(
      new Command("install")
        .description("Install the memshell-party skill into an agent's skill directory")
        .option("--user", "install to ~/.agents/skills (default)")
        .option("--claude", "install to ~/.claude/skills (Claude Code)")
        .option("--project [dir]", "install to <dir>/skills (default: current directory)")
        .option("--json", "output raw JSON")
        .addHelpText(
          "after",
          `
The package ships skills/memshell-party/SKILL.md — the workflow guide that
teaches an agent how to write site profiles, build custom shells and connect.
This command copies it where agents look for skills. Re-run after a CLI
upgrade to refresh the skill. Restart/rescan your agent to pick it up.

Examples:
  $ memparty skill install                  # ~/.agents/skills/memshell-party
  $ memparty skill install --claude         # ~/.claude/skills/memshell-party
  $ memparty skill install --project        # ./skills/memshell-party
  $ memparty skill install --user --claude  # both
`,
        )
        .action((opts: SkillInstallCmdOptions) => {
          const scopes: SkillScope[] = [];
          if (opts.user) scopes.push("user");
          if (opts.claude) scopes.push("claude");
          if (opts.project !== undefined && opts.project !== false) {
            scopes.push("project");
          }
          if (scopes.length === 0) scopes.push("user");

          const projectDir = typeof opts.project === "string" ? opts.project : undefined;
          try {
            const results = installSkill(scopes, { projectDir });
            logOp({
              category: "gen",
              action: "skill-install",
              ok: true,
              detail: results.map((r) => `${r.scope}:${r.dir}`).join(", "),
            });
            if (opts.json) {
              process.stdout.write(`${JSON.stringify({ ok: true, installed: results }, null, 2)}\n`);
              return;
            }
            for (const r of results) {
              logInfo(`installed [${r.scope}] ${r.dir} (${r.files.join(", ")})`);
            }
            process.stdout.write(
              "\nskill installed — restart or rescan your agent to pick it up.\n",
            );
          } catch (err) {
            reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
            process.exitCode = 1;
          }
        }),
    );
}
