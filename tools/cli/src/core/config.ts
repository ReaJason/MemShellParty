import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_API_URL = "https://party.mem.mk";
export const ENV_VAR = "MEMPARTY_API_URL";

export interface ResolveApiUrlInput {
  /** Value from the --api flag (highest priority). */
  flag?: string;
  /** Environment map (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** Home directory (defaults to os.homedir()). Injectable for tests. */
  home?: string;
}

interface RcFile {
  apiUrl?: string;
}

function readRcFile(home: string): RcFile | undefined {
  const path = join(home, ".mempartyrc");
  try {
    const raw = readFileSync(path, "utf8");
    return JSON.parse(raw) as RcFile;
  } catch {
    return undefined;
  }
}

/**
 * Resolve the API base URL by priority:
 *   1. --api flag
 *   2. MEMPARTY_API_URL env var
 *   3. ~/.mempartyrc  { "apiUrl": "..." }
 *   4. default public site (https://party.mem.mk)
 */
export function resolveApiUrl(input: ResolveApiUrlInput = {}): string {
  const env = input.env ?? process.env;
  const home = input.home ?? homedir();

  const fromFlag = input.flag?.trim();
  if (fromFlag) return fromFlag;

  const fromEnv = env[ENV_VAR]?.trim();
  if (fromEnv) return fromEnv;

  const fromFile = readRcFile(home)?.apiUrl?.trim();
  if (fromFile) return fromFile;

  return DEFAULT_API_URL;
}
