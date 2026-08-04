import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installSkill, skillSourceDir, skillTargetDir } from "./skill-install.js";

let dir: string;
let src: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "memparty-skill-"));
  src = join(dir, "fake-skill-src");
  mkdirSync(src, { recursive: true });
  writeFileSync(join(src, "SKILL.md"), "# fake skill v1\n", "utf8");
  writeFileSync(join(src, "extra.txt"), "extra\n", "utf8");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("skillTargetDir", () => {
  it("maps scopes to the agents' skill directories", () => {
    expect(skillTargetDir("user")).toContain(join(".agents", "skills", "memshell-party"));
    expect(skillTargetDir("claude")).toContain(join(".claude", "skills", "memshell-party"));
    expect(skillTargetDir("project", "/x/proj")).toBe(join("/x/proj", "skills", "memshell-party"));
  });
});

describe("skillSourceDir", () => {
  it("finds the bundled skill in the repo layout", () => {
    const p = skillSourceDir();
    expect(p).toContain(join("skills", "memshell-party"));
    expect(readFileSync(join(p, "SKILL.md"), "utf8")).toContain("name: memshell-party");
  });
});

describe("installSkill", () => {
  it("copies the skill into the target dir and reports the files", () => {
    const [result] = installSkill(["project"], { projectDir: dir, sourceDir: src });
    expect(result!.dir).toBe(join(dir, "skills", "memshell-party"));
    expect(result!.files).toEqual(["SKILL.md", "extra.txt"]);
    expect(readFileSync(join(result!.dir, "SKILL.md"), "utf8")).toBe("# fake skill v1\n");
  });

  it("overwrites a previous install (upgrade path)", () => {
    installSkill(["project"], { projectDir: dir, sourceDir: src });
    writeFileSync(join(src, "SKILL.md"), "# fake skill v2\n", "utf8");
    const [result] = installSkill(["project"], { projectDir: dir, sourceDir: src });
    expect(readFileSync(join(result!.dir, "SKILL.md"), "utf8")).toBe("# fake skill v2\n");
  });

  it("installs into multiple scopes in one call", () => {
    const results = installSkill(["project", "project"], {
      projectDir: dir,
      sourceDir: src,
    });
    expect(results).toHaveLength(2);
  });
});
