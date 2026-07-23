/**
 * Protocol registry — the single place that knows which shell protocols
 * exist and what each one can do.
 *
 * Commands (connect/exec/upload/download) no longer switch on a hardcoded
 * tool name: they look the protocol up here and call through the
 * `ShellProtocol` interface. The three built-in tools are registered as
 * thin adapters — their modules (`godzilla.ts` etc.) are untouched — and
 * plugins like `mimic` register the same way.
 */
import type { ResolvedConnection } from "../core/targets.js";
import {
  downloadBehinder,
  execBehinder,
  testBehinder,
  uploadBehinder,
} from "./behinder.js";
import {
  downloadGodzilla,
  execGodzilla,
  testGodzilla,
  uploadGodzilla,
} from "./godzilla.js";
import { testSuo5, type Suo5Mode } from "./suo5.js";
import { mimicProtocol } from "./mimic.js";
import type {
  CommonConnectOptions,
  ConnectTestResult,
  DownloadResult,
  ExecResult,
  TransferResult,
} from "./types.js";

/** Per-protocol extras collected from CLI flags / saved targets. */
export interface ProtocolOptions {
  /** godzilla: remote OS family for the shell wrapper. */
  os?: "auto" | "windows" | "linux";
  /** suo5: protocol variant. */
  suo5Mode?: Suo5Mode;
  /** godzilla: charset for non-ASCII remote paths. */
  remoteCharset?: string;
  /** mimic: site profile name (see 'memparty profile'). */
  profile?: string;
  /** mimic: randomize the request path from the site profile. */
  dynamicPath?: boolean;
}

/** Everything a protocol handler needs for one operation. */
export interface ProtocolRequest {
  conn: ResolvedConnection;
  common: CommonConnectOptions;
  options: ProtocolOptions;
}

export type Capability = "exec" | "upload" | "download";

export interface ShellProtocol {
  readonly name: string;
  /** One-line summary shown in help/listing. */
  readonly description?: string;
  /** Handshake / credentials check. */
  test(req: ProtocolRequest): Promise<ConnectTestResult>;
  exec?(req: ProtocolRequest, command: string): Promise<ExecResult>;
  upload?(req: ProtocolRequest, remotePath: string, data: Buffer): Promise<TransferResult>;
  download?(req: ProtocolRequest, remotePath: string): Promise<DownloadResult>;
}

const protocols = new Map<string, ShellProtocol>();

export function registerProtocol(protocol: ShellProtocol): void {
  protocols.set(protocol.name, protocol);
}

export function getProtocol(name: string): ShellProtocol | undefined {
  return protocols.get(name);
}

/** Names of registered protocols, optionally filtered by capability. */
export function protocolNames(capability?: Capability): string[] {
  const all = [...protocols.values()];
  const usable = capability ? all.filter((p) => p[capability] !== undefined) : all;
  return usable.map((p) => p.name);
}

/**
 * Look up a protocol or throw an error naming the available ones — this is
 * the message a user sees for a typo'd `--tool`.
 */
export function requireProtocol(name: string): ShellProtocol {
  const protocol = getProtocol(name);
  if (!protocol) {
    throw new Error(`unknown protocol ${JSON.stringify(name)} (available: ${protocolNames().join(", ")})`);
  }
  return protocol;
}

/** Error message when a protocol lacks the requested capability. */
export function unsupportedMessage(protocol: ShellProtocol, capability: Capability): string {
  return `protocol '${protocol.name}' does not support ${capability}`;
}

// ---- built-in adapters (wrap the existing modules, internals unchanged) ----

const godzillaProtocol: ShellProtocol = {
  name: "godzilla",
  description: "Godzilla JAVA_AES_BASE64 shell",
  test: ({ conn, common }) =>
    testGodzilla(conn.url, conn.pass ?? "pass", conn.key ?? "key", common),
  exec: ({ conn, common, options }, command) =>
    execGodzilla(conn.url, conn.pass ?? "pass", conn.key ?? "key", command, {
      ...common,
      os: options.os,
    }),
  upload: ({ conn, common, options }, remotePath, data) =>
    uploadGodzilla(conn.url, conn.pass ?? "pass", conn.key ?? "key", remotePath, data, {
      ...common,
      remoteCharset: options.remoteCharset,
    }),
  download: ({ conn, common, options }, remotePath) =>
    downloadGodzilla(conn.url, conn.pass ?? "pass", conn.key ?? "key", remotePath, {
      ...common,
      remoteCharset: options.remoteCharset,
    }),
};

const behinderProtocol: ShellProtocol = {
  name: "behinder",
  description: "Behinder AES shell",
  test: ({ conn, common }) => testBehinder(conn.url, conn.pass ?? "rebeyond", common),
  exec: ({ conn, common }, command) =>
    execBehinder(conn.url, conn.pass ?? "rebeyond", command, common),
  upload: ({ conn, common }, remotePath, data) =>
    uploadBehinder(conn.url, conn.pass ?? "rebeyond", remotePath, data, common),
  download: ({ conn, common }, remotePath) =>
    downloadBehinder(conn.url, conn.pass ?? "rebeyond", remotePath, common),
};

const suo5Protocol: ShellProtocol = {
  name: "suo5",
  description: "suo5 HTTP tunnel (connect test only)",
  test: ({ conn, common, options }) => testSuo5(conn.url, { ...common, mode: options.suo5Mode }),
};

registerProtocol(godzillaProtocol);
registerProtocol(behinderProtocol);
registerProtocol(suo5Protocol);
registerProtocol(mimicProtocol);
