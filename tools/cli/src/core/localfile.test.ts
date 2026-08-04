import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readUploadFile, remoteBasename, resolveDownloadPath } from "./localfile.js";

describe("remoteBasename", () => {
  it("handles linux paths", () => {
    expect(remoteBasename("/etc/passwd")).toBe("passwd");
    expect(remoteBasename("/var/log/app/")).toBe("app");
  });

  it("handles windows paths", () => {
    expect(remoteBasename("C:\\Windows\\win.ini")).toBe("win.ini");
    expect(remoteBasename("C:\\temp\\")).toBe("temp");
  });

  it("handles bare names and mixed separators", () => {
    expect(remoteBasename("shell.jsp")).toBe("shell.jsp");
    expect(remoteBasename("C:/x\\y/z.bin")).toBe("z.bin");
  });

  it("returns empty for pathological input", () => {
    expect(remoteBasename("")).toBe("");
    expect(remoteBasename("///")).toBe("");
  });
});

describe("resolveDownloadPath", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "memparty-dl-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("defaults to ./<basename>", () => {
    const out = resolveDownloadPath("/etc/passwd", undefined, false);
    expect(out).toBe(join(process.cwd(), "passwd"));
  });

  it("joins an existing directory argument with the basename", () => {
    const out = resolveDownloadPath("C:\\Windows\\win.ini", dir, false);
    expect(out).toBe(join(dir, "win.ini"));
  });

  it("accepts an explicit file path", () => {
    const target = join(dir, "loot.bin");
    expect(resolveDownloadPath("/data/x", target, false)).toBe(target);
  });

  it("refuses to overwrite an existing file without force", () => {
    const target = join(dir, "exists.bin");
    writeFileSync(target, "old");
    expect(() => resolveDownloadPath("/data/x", target, false)).toThrow(/already exists/);
    expect(resolveDownloadPath("/data/x", target, true)).toBe(target);
  });

  it("refuses a missing parent directory", () => {
    expect(() => resolveDownloadPath("/data/x", join(dir, "nope", "x.bin"), false)).toThrow(
      /does not exist/,
    );
  });

  it("refuses when the derived default name collides with an existing directory", () => {
    mkdirSync(join(dir, "sub"));
    const cwd = process.cwd();
    process.chdir(dir);
    try {
      expect(() => resolveDownloadPath("/data/sub", undefined, true)).toThrow(/directory/);
    } finally {
      process.chdir(cwd);
    }
  });

  it("demands -o when no basename can be derived", () => {
    expect(() => resolveDownloadPath("///", undefined, false)).toThrow(/pass -o/);
  });
});

describe("readUploadFile", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "memparty-ul-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reads a regular file byte-for-byte", () => {
    const target = join(dir, "a.bin");
    const bytes = Buffer.from([0, 1, 2, 255, 254, 3]);
    writeFileSync(target, bytes);
    expect(readUploadFile(target).equals(bytes)).toBe(true);
  });

  it("rejects missing files", () => {
    expect(() => readUploadFile(join(dir, "nope"))).toThrow(/does not exist/);
  });

  it("rejects directories", () => {
    expect(() => readUploadFile(dir)).toThrow(/not a regular file/);
  });

  it("rejects files over the size limit", () => {
    const target = join(dir, "big.bin");
    writeFileSync(target, Buffer.alloc(1024));
    expect(() => readUploadFile(target, 512)).toThrow(/over the 512-byte/);
  });
});
