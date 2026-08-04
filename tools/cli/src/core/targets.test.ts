import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  autoSaveShell,
  getProject,
  listProjects,
  removeProject,
  removeShell,
  resolveConnection,
  saveProjectMeta,
  saveShell,
  saveShellMeta,
} from "./targets.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "memparty-targets-"));
  process.env.MEMPARTY_TARGETS = join(dir, "targets.json");
});

afterEach(() => {
  delete process.env.MEMPARTY_TARGETS;
  rmSync(dir, { recursive: true, force: true });
});

const shell = {
  url: "http://192.0.2.1/shell.jsp",
  tool: "behinder" as const,
  pass: "rebeyond",
  headerName: "User-Agent",
  headerValue: "gate123",
};

describe("target store", () => {
  it("saves and lists projects with shells", () => {
    saveShell("web1", "bh9060", shell);
    saveShell("web1", "gdz8080", { ...shell, tool: "godzilla", key: "key" });
    saveShell("lab", "s1", shell);

    const projects = listProjects();
    expect(Object.keys(projects).sort()).toEqual(["lab", "web1"]);
    expect(Object.keys(projects["web1"]!.shells).sort()).toEqual(["bh9060", "gdz8080"]);
  });

  it("keeps createdAt when overwriting a shell", () => {
    const first = saveShell("p", "s", shell);
    const second = saveShell("p", "s", { ...shell, pass: "newpass" });
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.pass).toBe("newpass");
    expect(getProject("p")!.shells["s"]!.pass).toBe("newpass");
  });

  it("merges project remark/category and clears them on empty string", () => {
    saveShell("p", "s", shell);
    saveProjectMeta("p", { remark: "内网测试", category: "test" });
    expect(getProject("p")!.remark).toBe("内网测试");
    saveProjectMeta("p", { category: "prod" });
    expect(getProject("p")!.remark).toBe("内网测试"); // untouched
    expect(getProject("p")!.category).toBe("prod");
    saveProjectMeta("p", { remark: "", category: "" });
    expect(getProject("p")!.remark).toBeUndefined();
    expect(getProject("p")!.category).toBeUndefined();
  });

  it("stores a shell remark, preserves it on overwrite, clears via meta", () => {
    saveShell("p", "s", { ...shell, remark: "DMZ 跳板" });
    expect(getProject("p")!.shells["s"]!.remark).toBe("DMZ 跳板");
    // overwrite without remark -> old remark kept
    saveShell("p", "s", { ...shell, pass: "newpass" });
    expect(getProject("p")!.shells["s"]!.remark).toBe("DMZ 跳板");
    // overwrite with a new remark -> replaced
    saveShell("p", "s", { ...shell, remark: "新备注" });
    expect(getProject("p")!.shells["s"]!.remark).toBe("新备注");
    // clear via meta
    saveShellMeta("p", "s", { remark: "" });
    expect(getProject("p")!.shells["s"]!.remark).toBeUndefined();
    expect(() => saveShellMeta("p", "nope", { remark: "x" })).toThrow(/unknown shell/);
  });

  it("removes shells and projects", () => {
    saveShell("p", "s1", shell);
    saveShell("p", "s2", shell);
    expect(removeShell("p", "s1")).toBe(true);
    expect(removeShell("p", "nope")).toBe(false);
    expect(Object.keys(getProject("p")!.shells)).toEqual(["s2"]);
    expect(removeProject("p")).toBe(true);
    expect(removeProject("p")).toBe(false);
    expect(listProjects()).toEqual({});
  });

  it("rejects invalid names", () => {
    expect(() => saveShell("bad name", "s", shell)).toThrow(/invalid project name/);
    expect(() => saveShell("p", "bad/name", shell)).toThrow(/invalid shell name/);
  });
});

describe("resolveConnection", () => {
  it("resolves a full project/shell reference", () => {
    saveShell("web1", "bh9060", shell);
    const conn = resolveConnection("web1/bh9060", {});
    expect(conn.url).toBe(shell.url);
    expect(conn.tool).toBe("behinder");
    expect(conn.pass).toBe("rebeyond");
    expect(conn.headerValue).toBe("gate123");
    expect(conn.targetName).toBe("web1/bh9060");
  });

  it("resolves a bare project holding exactly one shell", () => {
    saveShell("web1", "only", shell);
    const conn = resolveConnection("web1", {});
    expect(conn.targetName).toBe("web1/only");
  });

  it("asks for a shell when a bare project holds several", () => {
    saveShell("web1", "a", shell);
    saveShell("web1", "b", shell);
    expect(() => resolveConnection("web1", {})).toThrow(/pick one: web1\/a, web1\/b/);
  });

  it("lets explicit flags override stored values", () => {
    saveShell("web1", "bh9060", shell);
    const conn = resolveConnection("web1/bh9060", { pass: "override", headerValue: "h2" });
    expect(conn.pass).toBe("override");
    expect(conn.headerValue).toBe("h2");
    expect(conn.headerName).toBe("User-Agent");
  });

  it("throws for unknown projects and shells", () => {
    saveShell("web1", "a", shell);
    expect(() => resolveConnection("nope", {})).toThrow(/unknown project/);
    expect(() => resolveConnection("web1/nope", {})).toThrow(/unknown shell/);
  });

  it("falls back to pure flags without a stored target", () => {
    const conn = resolveConnection(undefined, { url: "http://x/s.jsp", tool: "godzilla" });
    expect(conn.url).toBe("http://x/s.jsp");
    expect(conn.targetName).toBeUndefined();
    expect(() => resolveConnection(undefined, { tool: "godzilla" })).toThrow(/no URL/);
    expect(() => resolveConnection(undefined, { url: "http://x" })).toThrow(/--tool is required/);
  });
});

describe("autoSaveShell", () => {
  const conn = {
    url: "http://192.0.2.1:8080/shell.jsp",
    tool: "behinder" as const,
    pass: "rebeyond",
    headerName: "User-Agent",
    headerValue: "gate123",
    extraHeaders: {},
  };

  it("derives <host>/<tool> and resolves afterwards", () => {
    const name = autoSaveShell(conn);
    expect(name).toBe("192.0.2.1/behinder");
    const resolved = resolveConnection("192.0.2.1", {});
    expect(resolved.url).toBe(conn.url);
    expect(resolved.pass).toBe("rebeyond");
    expect(resolved.headerValue).toBe("gate123");
  });

  it("overwrites when the same URL is saved again", () => {
    autoSaveShell(conn);
    const name = autoSaveShell({ ...conn, pass: "newpass" });
    expect(name).toBe("192.0.2.1/behinder");
    expect(Object.keys(getProject("192.0.2.1")!.shells)).toEqual(["behinder"]);
    expect(getProject("192.0.2.1")!.shells["behinder"]!.pass).toBe("newpass");
  });

  it("suffixes a different URL on the same host+tool", () => {
    autoSaveShell(conn);
    const name = autoSaveShell({ ...conn, url: "http://192.0.2.1:8080/other.jsp" });
    expect(name).toBe("192.0.2.1/behinder-8080");
  });

  it("keeps tools separated on the same host", () => {
    autoSaveShell(conn);
    const name = autoSaveShell({ ...conn, tool: "godzilla" });
    expect(name).toBe("192.0.2.1/godzilla");
  });

  it("sanitizes odd hostnames", () => {
    const name = autoSaveShell({ ...conn, url: "http://[::1]:9000/s.jsp" });
    expect(name).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/);
    expect(resolveConnection(name, {}).url).toBe("http://[::1]:9000/s.jsp");
  });
});
