/** Shared types for the shell connection testers. */

/**
 * Shell protocol name. Used to be a hardcoded union of the built-in tools;
 * now a free string — `src/connect/registry.ts` is the source of truth for
 * which protocols actually exist (built-ins + plugins like "mimic").
 */
export type ConnectTool = string;

export interface ConnectTestResult {
  ok: boolean;
  tool: ConnectTool;
  url: string;
  /** Human-readable success detail (echo size, session id, protocol variant...). */
  detail?: string;
  /** Human-readable failure reason. */
  error?: string;
  durationMs: number;
}

export interface ExecResult {
  ok: boolean;
  tool: ConnectTool;
  url: string;
  /** The command line as executed remotely. */
  command: string;
  /** Decoded remote stdout+stderr (present on success). */
  output?: string;
  /** Human-readable failure reason. */
  error?: string;
  durationMs: number;
}

export interface TransferResult {
  ok: boolean;
  tool: ConnectTool;
  url: string;
  direction: "upload" | "download";
  /** The remote file path as requested. */
  remotePath: string;
  /** Bytes transferred (present on success). */
  bytes?: number;
  /** Extra success note (e.g. "hash verification unavailable"). */
  detail?: string;
  /** Human-readable failure reason. */
  error?: string;
  durationMs: number;
}

export interface DownloadResult extends TransferResult {
  /** File contents (present on success). */
  data?: Buffer;
}

export interface CommonConnectOptions {
  /**
   * MemShellParty shells are gated by a header check:
   * the request must carry `headerName` containing `headerValue`
   * (both are reported by `memparty gen --json` as shellToolConfig).
   */
  headerName?: string;
  headerValue?: string;
  /** Extra request headers (already merged with the gate header). */
  extraHeaders?: Record<string, string>;
  timeoutMs?: number;
  insecure?: boolean;
}

/** Build the request headers for a tester: extra headers + gate header. */
export function buildHeaders(
  base: Record<string, string>,
  options: CommonConnectOptions,
): Record<string, string> {
  const headers = { ...base, ...options.extraHeaders };
  if (options.headerValue) {
    headers[options.headerName || "User-Agent"] = options.headerValue;
  }
  return headers;
}
