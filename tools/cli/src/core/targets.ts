/**
 * Named shell targets persisted to a JSON file, so a shell's URL +
 * credentials + gate header are saved once and later referenced by name:
 *   memparty exec web1/bh9060 --cmd "whoami"
 *
 * A **project** groups several shells that belong to one engagement, with
 * an optional remark and category. A shell reference is `<project>/<shell>`;
 * a bare project name resolves when it holds exactly one shell.
 *
 * Store location: ~/.memparty/targets.json (override with MEMPARTY_TARGETS).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import type { ConnectTool } from "../connect/types.js";

/** A saved shell connection profile, stored inside a project. */
export interface StoredShell {
  url: string;
  tool: ConnectTool;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
  extraHeaders?: Record<string, string>;
  insecure?: boolean;
  /** mimic protocol: site profile name (see 'memparty profile'). */
  profile?: string;
  /** Free-form note for this shell (e.g. "DMZ 跳板机"). */
  remark?: string;
  createdAt: string;
  updatedAt: string;
}

export type ShellInput = Omit<StoredShell, "createdAt" | "updatedAt">;

/** A named group of shells with a remark and a category. */
export interface StoredProject {
  remark?: string;
  category?: string;
  createdAt: string;
  updatedAt: string;
  shells: Record<string, StoredShell>;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function checkName(kind: string, name: string): void {
  if (!NAME_RE.test(name)) {
    throw new Error(
      `invalid ${kind} name ${JSON.stringify(name)} — use letters, digits, '.', '_', '-'`,
    );
  }
}

export function targetStorePath(): string {
  return process.env.MEMPARTY_TARGETS ?? join(homedir(), ".memparty", "targets.json");
}

export function listProjects(): Record<string, StoredProject> {
  try {
    const file = targetStorePath();
    if (!existsSync(file)) return {};
    const data: unknown = JSON.parse(readFileSync(file, "utf8"));
    if (data !== null && typeof data === "object" && !Array.isArray(data)) {
      return data as Record<string, StoredProject>;
    }
  } catch {
    // corrupted store — treat as empty rather than crash the CLI
  }
  return {};
}

export function getProject(name: string): StoredProject | null {
  return listProjects()[name] ?? null;
}

function writeProjects(projects: Record<string, StoredProject>): void {
  const file = targetStorePath();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(projects, null, 2)}\n`, { mode: 0o600 });
}

/** Create a project or update its remark/category (only given fields change). */
export function saveProjectMeta(
  name: string,
  meta: { remark?: string; category?: string },
): StoredProject {
  checkName("project", name);
  const projects = listProjects();
  const now = new Date().toISOString();
  const existing = projects[name];
  const norm = (v: string | undefined) => (v ? v : undefined);
  const project: StoredProject = {
    remark: meta.remark !== undefined ? norm(meta.remark) : existing?.remark,
    category: meta.category !== undefined ? norm(meta.category) : existing?.category,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    shells: existing?.shells ?? {},
  };
  projects[name] = project;
  writeProjects(projects);
  return project;
}

/** Save a shell under `<project>/<shell>`; creates the project if needed. */
export function saveShell(projectName: string, shellName: string, input: ShellInput): StoredShell {
  checkName("project", projectName);
  checkName("shell", shellName);
  const projects = listProjects();
  const now = new Date().toISOString();
  const project = projects[projectName] ?? {
    createdAt: now,
    updatedAt: now,
    shells: {},
  };
  const existing = project.shells[shellName];
  const stored: StoredShell = {
    ...input,
    // remark is merged (empty string clears); other fields are overwritten
    remark: input.remark !== undefined ? input.remark || undefined : existing?.remark,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  project.shells[shellName] = stored;
  project.updatedAt = now;
  projects[projectName] = project;
  writeProjects(projects);
  return stored;
}

/** Remove a whole project. Returns false when it did not exist. */
export function removeProject(name: string): boolean {
  const projects = listProjects();
  if (!(name in projects)) return false;
  delete projects[name];
  writeProjects(projects);
  return true;
}

/** Remove one shell from a project. Returns false when it did not exist. */
export function removeShell(projectName: string, shellName: string): boolean {
  const projects = listProjects();
  const project = projects[projectName];
  if (!project || !(shellName in project.shells)) return false;
  delete project.shells[shellName];
  project.updatedAt = new Date().toISOString();
  writeProjects(projects);
  return true;
}

/** Set or clear (empty string) a shell's remark. */
export function saveShellMeta(
  projectName: string,
  shellName: string,
  meta: { remark?: string },
): StoredShell {
  const projects = listProjects();
  const shell = projects[projectName]?.shells[shellName];
  if (!shell) {
    throw new Error(`unknown shell ${JSON.stringify(`${projectName}/${shellName}`)}`);
  }
  if (meta.remark !== undefined) {
    shell.remark = meta.remark || undefined;
  }
  const now = new Date().toISOString();
  shell.updatedAt = now;
  projects[projectName]!.updatedAt = now;
  writeProjects(projects);
  return shell;
}

/** CLI/MCP flags that can override a stored shell's values. */
export interface ConnectionFlags {
  url?: string;
  tool?: string;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
  extraHeaders?: Record<string, string>;
  insecure?: boolean;
  profile?: string;
}

export interface ResolvedConnection {
  url: string;
  tool: ConnectTool;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
  extraHeaders: Record<string, string>;
  insecure?: boolean;
  /** mimic protocol: site profile name. */
  profile?: string;
  /** Canonical `project/shell` reference, when resolved from the store. */
  targetName?: string;
}

function sanitizeName(name: string): string {
  const s = name.replace(/[^A-Za-z0-9._-]/g, "_");
  return /^[A-Za-z0-9]/.test(s) ? s : `x${s}`;
}

/**
 * Auto-save a verified connection under a derived `<host>/<tool>` name and
 * return the canonical reference. A slot already pointing at the same URL is
 * overwritten; a name taken by a different URL gets a numeric/port suffix.
 */
export function autoSaveShell(conn: ResolvedConnection): string {
  let host = "target";
  let port = "";
  try {
    const u = new URL(conn.url);
    host = u.hostname || host;
    port = u.port;
  } catch {
    // keep the fallback name
  }
  const projectName = sanitizeName(host) || "target";
  const existing = getProject(projectName)?.shells ?? {};

  let shellName = Object.keys(existing).find(
    (n) => existing[n]!.url === conn.url && existing[n]!.tool === conn.tool,
  );
  if (!shellName) {
    const base = sanitizeName(conn.tool) || "shell";
    shellName = base;
    if (existing[shellName]) shellName = port ? `${base}-${port}` : `${base}-2`;
    for (let i = 2; existing[shellName]; i++) shellName = `${base}-${i}`;
  }

  saveShell(projectName, shellName, {
    url: conn.url,
    tool: conn.tool,
    pass: conn.pass,
    key: conn.key,
    headerName: conn.headerName,
    headerValue: conn.headerValue,
    extraHeaders: Object.keys(conn.extraHeaders).length > 0 ? conn.extraHeaders : undefined,
    insecure: conn.insecure,
    profile: conn.profile,
  });
  return `${projectName}/${shellName}`;
}

/**
 * Merge an optional saved shell reference (`<project>/<shell>` or a bare
 * project holding exactly one shell) with explicit flags.
 * Priority: explicit flag > stored value.
 */
export function resolveConnection(
  ref: string | undefined,
  flags: ConnectionFlags,
): ResolvedConnection {
  let stored: StoredShell | undefined;
  let targetName: string | undefined;

  if (ref) {
    const slash = ref.indexOf("/");
    const projectName = slash === -1 ? ref : ref.slice(0, slash);
    let shellName = slash === -1 ? undefined : ref.slice(slash + 1);

    const project = getProject(projectName);
    if (!project) {
      throw new Error(`unknown project ${JSON.stringify(projectName)} — see 'memparty list'`);
    }
    if (!shellName) {
      const names = Object.keys(project.shells);
      if (names.length === 0) {
        throw new Error(`project ${JSON.stringify(projectName)} has no shells yet`);
      }
      if (names.length > 1) {
        throw new Error(
          `project ${JSON.stringify(projectName)} has ${names.length} shells — pick one: ` +
            names.map((n) => `${projectName}/${n}`).join(", "),
        );
      }
      shellName = names[0]!;
    }
    stored = project.shells[shellName];
    if (!stored) {
      const known = Object.keys(project.shells);
      throw new Error(
        `unknown shell ${JSON.stringify(ref)} — project ${JSON.stringify(projectName)} has: ` +
          (known.length > 0 ? known.join(", ") : "(none)"),
      );
    }
    targetName = `${projectName}/${shellName}`;
  }

  const tool = (flags.tool ?? stored?.tool) as ConnectTool | undefined;
  const url = flags.url ?? stored?.url;
  if (!url) {
    throw new Error("no URL — pass --url or a saved target name");
  }
  if (!tool) {
    throw new Error("--tool is required — see the command's --help for available protocols");
  }
  return {
    url,
    tool,
    pass: flags.pass ?? stored?.pass,
    key: flags.key ?? stored?.key,
    headerName: flags.headerName ?? stored?.headerName,
    headerValue: flags.headerValue ?? stored?.headerValue,
    extraHeaders: { ...stored?.extraHeaders, ...flags.extraHeaders },
    insecure: flags.insecure ?? stored?.insecure,
    profile: flags.profile ?? stored?.profile,
    targetName,
  };
}
