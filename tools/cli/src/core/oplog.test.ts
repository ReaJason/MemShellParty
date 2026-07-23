import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { formatOp, logOp, readOps, truncateOutput, OUTPUT_LIMIT } from "./oplog.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "memparty-oplog-"));
  process.env.MEMPARTY_OPLOG = join(dir, "operations.jsonl");
});

afterEach(() => {
  delete process.env.MEMPARTY_OPLOG;
  rmSync(dir, { recursive: true, force: true });
});

describe("logOp / readOps", () => {
  it("appends entries and reads them newest-first", () => {
    logOp({ category: "connect", action: "connect", targetName: "web1/bh9060", ok: true });
    logOp({ category: "exec", action: "exec", targetName: "web1/bh9060", ok: true, command: "id" });
    const entries = readOps();
    expect(entries).toHaveLength(2);
    expect(entries[0]!.category).toBe("exec"); // newest first
    expect(entries[1]!.category).toBe("connect");
    expect(entries[0]!.ts).toBeTruthy();
  });

  it("filters by category", () => {
    logOp({ category: "connect", action: "connect", ok: true });
    logOp({ category: "exec", action: "exec", ok: true, command: "id" });
    logOp({ category: "save", action: "save", ok: true });
    const entries = readOps({ category: "exec" });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.command).toBe("id");
  });

  it("filters by target: project prefix and URL substring", () => {
    logOp({ category: "exec", action: "exec", targetName: "web1/bh9060", ok: true });
    logOp({ category: "exec", action: "exec", targetName: "web1/gdz8080", ok: true });
    logOp({ category: "exec", action: "exec", targetName: "other/s1", ok: true });
    logOp({ category: "connect", action: "connect", url: "http://10.0.0.5/x.jsp", ok: true });

    expect(readOps({ target: "web1" })).toHaveLength(2);
    expect(readOps({ target: "web1/bh9060" })).toHaveLength(1);
    expect(readOps({ target: "10.0.0.5" })).toHaveLength(1);
  });

  it("respects the limit", () => {
    for (let i = 0; i < 10; i++) {
      logOp({ category: "exec", action: "exec", ok: true, command: `cmd${i}` });
    }
    const entries = readOps({ limit: 3 });
    expect(entries).toHaveLength(3);
    expect(entries[0]!.command).toBe("cmd9");
  });

  it("returns an empty list when the log does not exist", () => {
    expect(readOps()).toEqual([]);
  });
});

describe("truncateOutput", () => {
  it("keeps short output intact", () => {
    expect(truncateOutput("hello")).toEqual({ output: "hello", truncated: false });
  });

  it("truncates long output", () => {
    const long = "x".repeat(OUTPUT_LIMIT + 100);
    const { output, truncated } = truncateOutput(long);
    expect(truncated).toBe(true);
    expect(output).toHaveLength(OUTPUT_LIMIT);
  });
});

describe("formatOp", () => {
  it("renders exec entries with command and first output line", () => {
    const line = formatOp({
      ts: "2026-07-18T09:30:01.000Z",
      category: "exec",
      action: "exec",
      targetName: "web1/bh9060",
      ok: true,
      durationMs: 19,
      command: "whoami && id",
      output: "root\nuid=0(root)",
    });
    expect(line).toContain("exec");
    expect(line).toContain("ok");
    expect(line).toContain("web1/bh9060");
    expect(line).toContain("$ whoami && id → root…");
    expect(line).toContain("(19ms)");
  });

  it("renders failures with the error", () => {
    const line = formatOp({
      ts: "2026-07-18T09:30:01.000Z",
      category: "connect",
      action: "connect",
      url: "http://x/s.jsp",
      ok: false,
      error: "wrong password",
    });
    expect(line).toContain("FAIL");
    expect(line).toContain("wrong password");
  });
});
