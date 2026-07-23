import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MemPartyClient } from "../api/client.js";
import { aesEcbDecrypt, aesEcbEncrypt, md5Hex, md5Key16 } from "../connect/crypto.js";
import { readStringConstant } from "../connect/classfile.js";
import { createMcpServer } from "./server.js";

const GATE = "mcp-gate";
const BH_KEY = md5Key16("rebeyond");

/** Tiny Behinder mock (same protocol as connect/behinder.test.ts). */
function startBehinderMock(files: Map<string, Buffer> = new Map()): Promise<Server> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const fail = () => res.writeHead(200).end();
      if (!(req.headers["user-agent"] ?? "").includes(GATE)) return fail();
      let classBytes: Buffer;
      try {
        classBytes = aesEcbDecrypt(
          Buffer.from(Buffer.concat(chunks).toString("latin1").trim(), "base64"),
          BH_KEY,
        );
      } catch {
        return fail();
      }
      const envelope = (status: string, msg: string) =>
        Buffer.from(
          aesEcbEncrypt(
            Buffer.from(
              JSON.stringify({
                status: Buffer.from(status).toString("base64"),
                msg: Buffer.from(msg, "utf8").toString("base64"),
              }),
            ),
            BH_KEY,
          ).toString("base64"),
        );

      // FileOperation payload: dispatched on the `mode` field
      const mode = readStringConstant(classBytes, "mode");
      if (mode !== null) {
        const path = readStringConstant(classBytes, "path") ?? "";
        const content = readStringConstant(classBytes, "content");
        const blockIndex = Number(readStringConstant(classBytes, "blockIndex") ?? "0");
        const blockSize = Number(readStringConstant(classBytes, "blockSize") ?? "0");
        switch (mode) {
          case "checkExist": {
            const f = files.get(path);
            res.writeHead(200).end(f === undefined ? envelope("fail", "") : envelope("success", String(f.length)));
            return;
          }
          case "create": {
            const data = Buffer.from(content ?? "", "base64");
            files.set(path, data);
            res.writeHead(200).end(envelope("success", `${path}上传完成，远程文件大小:${data.length}`));
            return;
          }
          case "append": {
            const data = Buffer.from(content ?? "", "base64");
            files.set(path, Buffer.concat([files.get(path) ?? Buffer.alloc(0), data]));
            res.writeHead(200).end(envelope("success", `${path}追加完成`));
            return;
          }
          case "downloadPart": {
            const f = files.get(path);
            if (f === undefined) {
              res.writeHead(200).end(envelope("fail", "FileNotFoundException"));
              return;
            }
            const pos = blockIndex * blockSize;
            if (pos >= f.length) {
              res.writeHead(200).end(envelope("fail", ""));
              return;
            }
            res.writeHead(200).end(
              envelope("success", f.subarray(pos, Math.min(pos + blockSize, f.length)).toString("base64")),
            );
            return;
          }
          case "check": {
            const f = files.get(path);
            if (f === undefined || f.length === 0) {
              res.writeHead(200).end();
              return;
            }
            res.writeHead(200).end(envelope("success", md5Hex(f).slice(0, 16)));
            return;
          }
          default:
            res.writeHead(200).end(envelope("fail", `unsupported mode ${mode}`));
            return;
        }
      }

      const content = readStringConstant(classBytes, "content");
      if (content === null) {
        // Cmd payload: answer with the injected `cmd` field
        const cmd = readStringConstant(classBytes, "cmd") ?? "";
        const json = JSON.stringify({
          status: Buffer.from("success").toString("base64"),
          msg: Buffer.from(`MOCK-EXEC:${cmd}`).toString("base64"),
        });
        res.writeHead(200).end(Buffer.from(aesEcbEncrypt(Buffer.from(json), BH_KEY).toString("base64")));
        return;
      }
      const json = JSON.stringify({
        status: Buffer.from("success").toString("base64"),
        msg: Buffer.from(content).toString("base64"),
      });
      res.writeHead(200).end(Buffer.from(aesEcbEncrypt(Buffer.from(json), BH_KEY).toString("base64")));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

interface ToolResult {
  isError?: boolean;
  content: Array<{ type: string; text: string }>;
}

describe("MCP connect_test tool", () => {
  let httpServer: Server;
  let base: string;
  let mcpClient: Client;
  let tmpDir: string;
  const remoteFiles = new Map<string, Buffer>();

  beforeAll(async () => {
    // keep test operations out of the real global op log and target store
    tmpDir = mkdtempSync(join(tmpdir(), "memparty-mcp-test-"));
    process.env.MEMPARTY_OPLOG = join(tmpDir, "operations.jsonl");
    process.env.MEMPARTY_TARGETS = join(tmpDir, "targets.json");

    httpServer = await startBehinderMock(remoteFiles);
    base = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;

    const apiClient = new MemPartyClient({ baseUrl: "http://unused" });
    const mcpServer = createMcpServer(apiClient);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    mcpClient = new Client({ name: "test-client", version: "0.0.0" });
    await Promise.all([mcpClient.connect(clientTransport), mcpServer.connect(serverTransport)]);
  });

  afterAll(async () => {
    await mcpClient.close();
    await new Promise((resolve) => httpServer.close(resolve));
    delete process.env.MEMPARTY_OPLOG;
    delete process.env.MEMPARTY_TARGETS;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("lists connect_test with its input schema", async () => {
    const { tools } = await mcpClient.listTools();
    const tool = tools.find((t) => t.name === "connect_test");
    expect(tool).toBeDefined();
    expect(tool!.description).toContain("protocol handshake");
    const props = (tool!.inputSchema as { properties: Record<string, unknown> }).properties;
    expect(Object.keys(props)).toEqual(
      expect.arrayContaining(["url", "tool", "pass", "key", "headerName", "headerValue"]),
    );
  });

  it("reports ok=true for a working shell", async () => {
    const result = (await mcpClient.callTool({
      name: "connect_test",
      arguments: {
        url: `${base}/behinder`,
        tool: "behinder",
        pass: "rebeyond",
        headerValue: GATE,
      },
    })) as ToolResult;
    expect(result.isError).toBeFalsy();
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.ok).toBe(true);
    expect(payload.tool).toBe("behinder");
  });

  it("reports ok=false for a wrong password (not a protocol error)", async () => {
    const result = (await mcpClient.callTool({
      name: "connect_test",
      arguments: {
        url: `${base}/behinder`,
        tool: "behinder",
        pass: "wrongpass",
        headerValue: GATE,
      },
    })) as ToolResult;
    expect(result.isError).toBeFalsy();
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.ok).toBe(false);
    expect(payload.error).toBeTruthy();
  });

  describe("target tools", () => {
    let dir: string;

    beforeAll(() => {
      dir = mkdtempSync(join(tmpdir(), "memparty-mcp-targets-"));
      process.env.MEMPARTY_TARGETS = join(dir, "targets.json");
      process.env.MEMPARTY_OPLOG = join(dir, "operations.jsonl");
    });

    afterAll(() => {
      delete process.env.MEMPARTY_TARGETS;
      delete process.env.MEMPARTY_OPLOG;
      rmSync(dir, { recursive: true, force: true });
    });

    it("saves a target with project meta", async () => {
      const result = (await mcpClient.callTool({
        name: "target_save",
        arguments: {
          project: "hw",
          shell: "bh",
          url: `${base}/behinder`,
          tool: "behinder",
          pass: "rebeyond",
          headerValue: GATE,
          projectRemark: "测试项目",
          projectCategory: "lab",
          shellRemark: "9060 冰蝎",
        },
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      const saved = JSON.parse(result.content[0]!.text);
      expect(saved.tool).toBe("behinder");
      expect(saved.url).toBe(`${base}/behinder`);
      expect(saved.remark).toBe("9060 冰蝎");
    });

    it("lists saved targets with remark and category", async () => {
      const result = (await mcpClient.callTool({
        name: "target_list",
        arguments: {},
      })) as ToolResult;
      const payload = JSON.parse(result.content[0]!.text);
      expect(payload.projects.hw.remark).toBe("测试项目");
      expect(payload.projects.hw.category).toBe("lab");
      expect(payload.projects.hw.shells.bh.remark).toBe("9060 冰蝎");
      expect(Object.keys(payload.projects.hw.shells)).toEqual(["bh"]);
    });

    it("runs connect_test by target name", async () => {
      const result = (await mcpClient.callTool({
        name: "connect_test",
        arguments: { name: "hw/bh" },
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      expect(JSON.parse(result.content[0]!.text).ok).toBe(true);
    });

    it("runs exec_command by target name", async () => {
      const result = (await mcpClient.callTool({
        name: "exec_command",
        arguments: { name: "hw/bh", command: "id" },
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]!.text);
      expect(payload.ok).toBe(true);
      expect(payload.output).toBe("MOCK-EXEC:id");
    });

    it("errors for an unknown target name", async () => {
      const result = (await mcpClient.callTool({
        name: "connect_test",
        arguments: { name: "nope/nothing" },
      })) as ToolResult;
      expect(result.isError).toBe(true);
      expect(result.content[0]!.text).toContain("unknown project");
    });

    it("removes the project", async () => {
      const result = (await mcpClient.callTool({
        name: "target_remove",
        arguments: { project: "hw" },
      })) as ToolResult;
      expect(JSON.parse(result.content[0]!.text).removed).toBe(true);
      const gone = (await mcpClient.callTool({
        name: "connect_test",
        arguments: { name: "hw/bh" },
      })) as ToolResult;
      expect(gone.isError).toBe(true);
    });

    it("logs every operation to the global op log", async () => {
      const result = (await mcpClient.callTool({
        name: "log_list",
        arguments: {},
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]!.text);
      const actions = payload.entries.map(
        (e: { category: string; action: string }) => `${e.category}:${e.action}`,
      );
      expect(actions).toContain("save:save");
      expect(actions).toContain("connect:connect");
      expect(actions).toContain("exec:exec");
      expect(actions).toContain("remove:remove");

      const execOnly = (await mcpClient.callTool({
        name: "log_list",
        arguments: { category: "exec" },
      })) as ToolResult;
      const filtered = JSON.parse(execOnly.content[0]!.text);
      expect(filtered.entries.length).toBeGreaterThan(0);
      expect(
        filtered.entries.every((e: { category: string }) => e.category === "exec"),
      ).toBe(true);
    });
  });

  describe("transfer tools", () => {
    const payloadBytes = Buffer.alloc(70_000);
    for (let i = 0; i < payloadBytes.length; i++) payloadBytes[i] = (i * 5 + 23) % 256;

    beforeAll(() => {
      // keep the auto-saved target out of the user's real target store
      process.env.MEMPARTY_TARGETS = join(tmpDir, "targets.json");
    });

    afterAll(() => {
      delete process.env.MEMPARTY_TARGETS;
    });

    it("lists download_file and upload_file with their schemas", async () => {
      const { tools } = await mcpClient.listTools();
      const download = tools.find((t) => t.name === "download_file");
      const upload = tools.find((t) => t.name === "upload_file");
      expect(download).toBeDefined();
      expect(upload).toBeDefined();
      const dlProps = (download!.inputSchema as { properties: Record<string, unknown> }).properties;
      expect(Object.keys(dlProps)).toEqual(
        expect.arrayContaining(["remotePath", "localPath", "force", "name", "url", "tool"]),
      );
    });

    it("uploads a multi-chunk file and auto-saves the target", async () => {
      const localFile = join(tmpDir, "mcp-upload.bin");
      writeFileSync(localFile, payloadBytes);
      const result = (await mcpClient.callTool({
        name: "upload_file",
        arguments: {
          url: `${base}/behinder`,
          tool: "behinder",
          pass: "rebeyond",
          headerValue: GATE,
          localPath: localFile,
          remotePath: "/remote/mcp.bin",
        },
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]!.text);
      expect(payload.ok).toBe(true);
      expect(payload.bytes).toBe(payloadBytes.length);
      expect(payload.savedAs).toBe("127.0.0.1/behinder");
      expect(remoteFiles.get("/remote/mcp.bin")?.equals(payloadBytes)).toBe(true);
    });

    it("downloads it back by the saved target name", async () => {
      const localFile = join(tmpDir, "mcp-download.bin");
      const result = (await mcpClient.callTool({
        name: "download_file",
        arguments: { name: "127.0.0.1/behinder", remotePath: "/remote/mcp.bin", localPath: localFile },
      })) as ToolResult;
      expect(result.isError).toBeFalsy();
      const payload = JSON.parse(result.content[0]!.text);
      expect(payload.ok).toBe(true);
      expect(payload.bytes).toBe(payloadBytes.length);
      expect(payload.data).toBeUndefined(); // file bytes never go over MCP
      expect(readFileSync(localFile).equals(payloadBytes)).toBe(true);
    });

    it("refuses to overwrite a local file without force", async () => {
      const localFile = join(tmpDir, "mcp-download.bin");
      const result = (await mcpClient.callTool({
        name: "download_file",
        arguments: { name: "127.0.0.1/behinder", remotePath: "/remote/mcp.bin", localPath: localFile },
      })) as ToolResult;
      expect(result.isError).toBe(true);
      expect(result.content[0]!.text).toMatch(/already exists/);

      const forced = (await mcpClient.callTool({
        name: "download_file",
        arguments: {
          name: "127.0.0.1/behinder",
          remotePath: "/remote/mcp.bin",
          localPath: localFile,
          force: true,
        },
      })) as ToolResult;
      expect(forced.isError).toBeFalsy();
      expect(JSON.parse(forced.content[0]!.text).ok).toBe(true);
    });

    it("errors on a missing local file for upload", async () => {
      const result = (await mcpClient.callTool({
        name: "upload_file",
        arguments: {
          name: "127.0.0.1/behinder",
          localPath: join(tmpDir, "no-such.bin"),
          remotePath: "/remote/never.bin",
        },
      })) as ToolResult;
      expect(result.isError).toBe(true);
      expect(result.content[0]!.text).toMatch(/does not exist/);
    });

    it("logs the transfers to the global op log", async () => {
      const result = (await mcpClient.callTool({
        name: "log_list",
        arguments: { category: "upload" },
      })) as ToolResult;
      const entries = JSON.parse(result.content[0]!.text).entries as Array<{
        category: string;
        meta?: { bytes?: number };
      }>;
      expect(entries.length).toBeGreaterThan(0);
      expect(entries.every((e) => e.category === "upload")).toBe(true);
      expect(entries[0]!.meta?.bytes).toBe(payloadBytes.length);
    });
  });
});
