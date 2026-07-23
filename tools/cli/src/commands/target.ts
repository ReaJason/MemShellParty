import { Command, Option } from "commander";

import {
  getProject,
  listProjects,
  removeProject,
  removeShell,
  saveProjectMeta,
  saveShell,
  saveShellMeta,
  targetStorePath,
  type ShellInput,
} from "../core/targets.js";
import { logOp } from "../core/oplog.js";

interface TargetSaveOptions {
  url?: string;
  tool?: string;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
  header?: string[];
  insecure?: boolean;
  remark?: string;
  category?: string;
  shellRemark?: string;
  json?: boolean;
}

function parseExtraHeaders(lines: string[] | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of lines ?? []) {
    const idx = line.indexOf(":");
    if (idx <= 0) {
      throw new Error(`invalid header ${JSON.stringify(line)}, expected "Name: value"`);
    }
    headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return headers;
}

function parseRef(ref: string): { project: string; shell?: string } {
  const slash = ref.indexOf("/");
  if (slash === -1) return { project: ref };
  return { project: ref.slice(0, slash), shell: ref.slice(slash + 1) };
}

function listTargets(opts: { category?: string; json?: boolean }): void {
  const all = listProjects();
  const names = Object.keys(all).filter(
    (n) => opts.category === undefined || all[n]!.category === opts.category,
  );
  if (opts.json) {
    const filtered: Record<string, unknown> = {};
    for (const n of names) filtered[n] = all[n];
    process.stdout.write(`${JSON.stringify(filtered, null, 2)}\n`);
    return;
  }
  if (names.length === 0) {
    process.stdout.write(`no saved projects (store: ${targetStorePath()})\n`);
    return;
  }
  for (const name of names) {
    const p = all[name]!;
    const meta =
      [p.category ? `[${p.category}]` : undefined, p.remark].filter(Boolean).join("  ");
    process.stdout.write(`${name}${meta ? `  ${meta}` : ""}\n`);
    for (const [shellName, s] of Object.entries(p.shells)) {
      const line = `  ${name}/${shellName}  ${s.tool}  ${s.url}`;
      process.stdout.write(`${line}${s.remark ? `  — ${s.remark}` : ""}\n`);
    }
  }
}

export function registerTargetCommand(program: Command): void {
  program
    .command("save")
    .description(
      "Save a shell connection profile as <project>/<shell> (overwrites an existing shell)",
    )
    .argument("<ref>", "shell reference: <project>/<shell>")
    .requiredOption("-u, --url <url>", "URL of the deployed shell")
    .addOption(
      new Option("-t, --tool <tool>", "shell tool").choices(["godzilla", "behinder", "suo5"]),
    )
    .option("--pass <pass>", "password")
    .option("--key <key>", "godzilla key")
    .option("--header-name <name>", "gate header name (shellToolConfig.headerName)")
    .option("--header-value <value>", "gate header value (shellToolConfig.headerValue)")
    .option("-H, --header <line...>", 'extra request header, e.g. -H "Cookie: a=b"')
    .option("-k, --insecure", "skip TLS certificate verification")
    .option("--remark <text>", "project remark (merged into the project)")
    .option("--category <name>", "project category (merged into the project)")
    .option("--shell-remark <text>", "remark for this shell")
    .option("--json", "output raw JSON")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty save web1/bh9060 -u http://192.0.2.10:9060/console/service \\
      -t behinder --pass rebeyond --header-name User-Agent --header-value my-secret-token \\
      --remark "内网测试环境" --category test
  $ memparty list                            # show saved targets
  $ memparty exec web1/bh9060 --cmd "whoami"

Note: connect/exec already auto-save a verified shell as <host>/<tool>;
save is for choosing the name by hand.
`,
    )
    .action((ref: string, opts: TargetSaveOptions) => {
      const { project, shell } = parseRef(ref);
      if (!shell) {
        process.stderr.write(
          `Error: expected <project>/<shell>, got ${JSON.stringify(ref)}\n`,
        );
        process.exitCode = 1;
        return;
      }
      if (!opts.tool) {
        process.stderr.write("Error: --tool is required (godzilla | behinder | suo5)\n");
        process.exitCode = 1;
        return;
      }
      if (opts.remark !== undefined || opts.category !== undefined) {
        saveProjectMeta(project, { remark: opts.remark, category: opts.category });
      }
      const input: ShellInput = {
        url: opts.url!,
        tool: opts.tool as ShellInput["tool"],
        pass: opts.pass,
        key: opts.key,
        headerName: opts.headerName,
        headerValue: opts.headerValue,
        extraHeaders: parseExtraHeaders(opts.header),
        insecure: opts.insecure || undefined,
        remark: opts.shellRemark,
      };
      const stored = saveShell(project, shell, input);
      logOp({
        category: "save",
        action: "save",
        targetName: `${project}/${shell}`,
        url: stored.url,
        tool: stored.tool,
        ok: true,
        detail: "saved",
        meta: {
          projectRemark: opts.remark,
          projectCategory: opts.category,
          shellRemark: opts.shellRemark,
        },
      });
      if (opts.json) {
        process.stdout.write(
          `${JSON.stringify({ project, shell, ...stored }, null, 2)}\n`,
        );
      } else {
        process.stdout.write(
          `saved ${project}/${shell} (${stored.tool} ${stored.url}) -> ${targetStorePath()}\n`,
        );
      }
    });

  program
    .command("note")
    .description("Set a remark/category on a project, or a remark on a shell (<project>[/<shell>])")
    .argument("<ref>", "project name or <project>/<shell>")
    .option("--remark <text>", 'remark ("" to clear)')
    .option("--category <name>", 'project category ("" to clear; projects only)')
    .action((ref: string, opts: { remark?: string; category?: string }) => {
      const { project, shell } = parseRef(ref);
      if (shell) {
        if (opts.category !== undefined) {
          process.stderr.write("Error: --category only applies to projects\n");
          process.exitCode = 1;
          return;
        }
        if (opts.remark === undefined) {
          process.stderr.write("Error: nothing to set — pass --remark\n");
          process.exitCode = 1;
          return;
        }
        const updated = saveShellMeta(project, shell, { remark: opts.remark });
        logOp({
          category: "note",
          action: "note",
          targetName: `${project}/${shell}`,
          ok: true,
          detail: `remark=${updated.remark ?? "-"}`,
        });
        process.stdout.write(`${project}/${shell}: remark=${updated.remark ?? "-"}\n`);
        return;
      }
      if (opts.remark === undefined && opts.category === undefined) {
        process.stderr.write("Error: nothing to set — pass --remark and/or --category\n");
        process.exitCode = 1;
        return;
      }
      const existing = getProject(project);
      if (!existing) {
        process.stderr.write(`Error: unknown project ${JSON.stringify(project)}\n`);
        process.exitCode = 1;
        return;
      }
      const updated = saveProjectMeta(project, {
        remark: opts.remark,
        category: opts.category,
      });
      logOp({
        category: "note",
        action: "note",
        targetName: project,
        ok: true,
        detail: `category=${updated.category ?? "-"} remark=${updated.remark ?? "-"}`,
      });
      process.stdout.write(
        `${project}: category=${updated.category ?? "-"} remark=${updated.remark ?? "-"}\n`,
      );
    });

  program
    .command("list")
    .description("List saved projects and their shells")
    .option("--category <name>", "only show projects in this category")
    .option("--json", "output raw JSON")
    .action(listTargets);

  program
    .command("remove")
    .description("Remove a whole project or a single shell (<project>[/<shell>])")
    .argument("<ref>", "project name or <project>/<shell>")
    .action((ref: string) => {
      const { project, shell } = parseRef(ref);
      const removed = shell ? removeShell(project, shell) : removeProject(project);
      logOp({
        category: "remove",
        action: "remove",
        targetName: ref,
        ok: removed,
        detail: removed ? "removed" : "unknown target",
      });
      if (removed) {
        process.stdout.write(`removed ${ref}\n`);
      } else {
        process.stderr.write(`Error: unknown target ${JSON.stringify(ref)}\n`);
        process.exitCode = 1;
      }
    });
}
