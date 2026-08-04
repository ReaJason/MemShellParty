/**
 * Install the bundled agent skill (`skills/memshell-party/SKILL.md`, shipped
 * in the npm package) into an agent's skill directory — `memparty skill
 * install`. Three scopes:
 *
 *   user    ~/.agents/skills/memshell-party    (Kimi Code and compatible)
 *   claude  ~/.claude/skills/memshell-party    (Claude Code)
 *   project <dir>/skills/memshell-party        (project-local, default cwd)
 *
 * The copy is a full overwrite — installing again after a CLI upgrade
 * refreshes the skill to the installed version.
 */
import { cpSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export type SkillScope = "user" | "claude" | "project";

export const SKILL_NAME = "memshell-party";

/** Locate the bundled skill directory (handles both src/ and dist/ layouts). */
export function skillSourceDir(): string {
  const candidates = [
    new URL(`../skills/${SKILL_NAME}`, import.meta.url), // dist/*.js
    new URL(`../../skills/${SKILL_NAME}`, import.meta.url), // src/core/*.ts
  ];
  for (const candidate of candidates) {
    const p = fileURLToPath(candidate);
    if (existsSync(p)) return p;
  }
  throw new Error(`bundled skill not found (expected skills/${SKILL_NAME} in the package)`);
}

export function skillTargetDir(scope: SkillScope, projectDir?: string): string {
  switch (scope) {
    case "user":
      return join(homedir(), ".agents", "skills", SKILL_NAME);
    case "claude":
      return join(homedir(), ".claude", "skills", SKILL_NAME);
    case "project":
      return join(projectDir ?? process.cwd(), "skills", SKILL_NAME);
  }
}

export interface SkillInstallResult {
  scope: SkillScope;
  dir: string;
  /** Top-level entries after the copy. */
  files: string[];
}

export interface InstallSkillOptions {
  /** Base dir for project scope (default: cwd). */
  projectDir?: string;
  /** Override the bundled skill source (tests). */
  sourceDir?: string;
}

/** Copy the bundled skill into each scope's directory. Overwrites. */
export function installSkill(
  scopes: SkillScope[],
  opts: InstallSkillOptions = {},
): SkillInstallResult[] {
  const src = opts.sourceDir ?? skillSourceDir();
  return scopes.map((scope) => {
    const dir = skillTargetDir(scope, opts.projectDir);
    mkdirSync(dir, { recursive: true });
    cpSync(src, dir, { recursive: true });
    return { scope, dir, files: readdirSync(dir).sort() };
  });
}
