import { MemPartyClient } from "./api/client.js";
import { resolveApiUrl } from "./core/config.js";

/** Global options attached to every command via commander. */
export interface GlobalOptions {
  api?: string;
  timeout?: string;
}

export function createClient(opts: GlobalOptions): MemPartyClient {
  const baseUrl = resolveApiUrl({ flag: opts.api });
  const timeoutMs = opts.timeout ? Number(opts.timeout) : undefined;
  return new MemPartyClient({ baseUrl, timeoutMs });
}

/** Write a message to stderr. */
export function logError(msg: string): void {
  process.stderr.write(`${msg}\n`);
}

/** Write an informational message to stderr (keeps stdout clean for payloads). */
export function logInfo(msg: string): void {
  process.stderr.write(`${msg}\n`);
}

/** Report a fatal error; as JSON when --json is in argv, so agents can parse it. */
export function reportError(message: string, argv: string[]): void {
  if (argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify({ ok: false, error: message })}\n`);
  } else {
    process.stderr.write(`Error: ${message}\n`);
  }
}
