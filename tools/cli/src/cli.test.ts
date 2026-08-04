/**
 * Subprocess smoke tests: run the built dist/cli.js the way an agent or a
 * shell would, and assert on stdout / stderr / exit code. These cover the
 * commander wiring layer that unit tests cannot see (option registration,
 * help text, exitOverride, REPL, JSON error mode).
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = join(__dirname, "..", "dist", "cli.js");

let storeDir: string;

beforeAll(() => {
  if (!existsSync(CLI)) {
    execFileSync("npm", ["run", "build"], { cwd: join(__dirname, ".."), stdio: "inherit" });
  }
  storeDir = mkdtempSync(join(tmpdir(), "memparty-cli-test-"));
});

afterAll(() => {
  rmSync(storeDir, { recursive: true, force: true });
});

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function run(args: string[], input?: string): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    input,
    encoding: "utf8",
    env: {
      ...process.env,
      MEMPARTY_TARGETS: join(storeDir, "targets.json"),
      MEMPARTY_OPLOG: join(storeDir, "operations.jsonl"),
    },
  });
  return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

describe("cli subprocess", () => {
  it("--help shows quick-start examples and exits 0", () => {
    const r = run(["--help"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Quick start:");
  });

  it("every documented subcommand help has examples", () => {
    for (const cmd of ["gen", "probe", "config", "connect", "exec", "save", "log"]) {
      const r = run([cmd, "--help"]);
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(/^Examples:$/m);
    }
  });

  it("unknown command exits 1", () => {
    expect(run(["definitely-not-a-command"]).status).toBe(1);
  });

  it("connect without URL exits 1 with a plain error", () => {
    const r = run(["connect"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no URL/);
  });

  it("with --json the same failure is a JSON document on stdout", () => {
    const r = run(["connect", "--json"]);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout) as { ok: boolean; error: string };
    expect(doc.ok).toBe(false);
    expect(doc.error).toMatch(/no URL/);
  });

  it("gen --no-interactive without required flags fails as JSON with --json", () => {
    const r = run(["gen", "--no-interactive", "--json"]);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout) as { ok: boolean; error: string };
    expect(doc.ok).toBe(false);
    expect(doc.error).toMatch(/Missing required option/);
  });

  it("list --json works fully offline", () => {
    const r = run(["list", "--json"]);
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({});
  });
});

describe("repl", () => {
  function repl(input: string): RunResult {
    const r = spawnSync(process.execPath, [CLI], {
      input,
      encoding: "utf8",
      env: {
        ...process.env,
        MEMPARTY_REPL: "1",
        MEMPARTY_TARGETS: join(storeDir, "targets.json"),
        MEMPARTY_OPLOG: join(storeDir, "operations.jsonl"),
      },
    });
    return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
  }

  it("executes commands line by line and exits 0", () => {
    const r = repl("list --json\nbadcmd\nquit\n");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("interactive mode");
    expect(r.stdout).toContain("{}"); // list output
    expect(r.stderr + r.stdout).toMatch(/unknown command/); // badcmd reported, loop kept going
  });

  it("JSON error mode works inside the REPL", () => {
    const r = repl("connect --json\nquit\n");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('"ok":false');
  });
});
