/**
 * Global operation log — every gen / probe / connect / exec / download /
 * upload / target operation is appended as one JSON line, giving an
 * auditable trail of what ran, against which target, and how it ended.
 *
 * Location: ~/.memparty/operations.jsonl (override with MEMPARTY_OPLOG).
 * Logging is best-effort: a broken log file/dir must never break the
 * operation being logged.
 *
 * Secrets are never logged: no pass/key/headerValue, no payload bytes,
 * no file contents. Exec output is truncated (see OUTPUT_LIMIT).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type OpCategory =
  | "gen"
  | "probe"
  | "connect"
  | "exec"
  | "download"
  | "upload"
  | "save"
  | "note"
  | "remove";

export interface OpLogEntry {
  /** ISO timestamp. */
  ts: string;
  category: OpCategory;
  /** What happened: "gen" | "probe" | "connect" | "exec" | "save" | "note" | "remove". */
  action: string;
  /** Saved `project/shell` reference, when the operation used one. */
  targetName?: string;
  url?: string;
  tool?: string;
  ok: boolean;
  durationMs?: number;
  /** Short human-readable success detail. */
  detail?: string;
  error?: string;
  /** exec only: the command line. */
  command?: string;
  /** exec only: remote output, truncated to OUTPUT_LIMIT. */
  output?: string;
  outputTruncated?: boolean;
  /** Extra structured fields (target meta, gen params — never credentials). */
  meta?: Record<string, unknown>;
}

/** exec output is truncated to this many characters in the log. */
export const OUTPUT_LIMIT = 2000;

export function opLogPath(): string {
  return process.env.MEMPARTY_OPLOG ?? join(homedir(), ".memparty", "operations.jsonl");
}

/** Append one entry. Never throws. */
export function logOp(entry: Omit<OpLogEntry, "ts">): void {
  try {
    const file = opLogPath();
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
  } catch {
    // best-effort logging — the operation itself already completed
  }
}

export interface OpFilter {
  category?: OpCategory;
  /**
   * Match by saved target reference ("web1" also matches "web1/bh9060")
   * or by a substring of the URL (e.g. a host).
   */
  target?: string;
  /** Max entries returned (default 50). */
  limit?: number;
}

/** Read entries matching the filter, newest first. */
export function readOps(filter: OpFilter = {}): OpLogEntry[] {
  let entries: OpLogEntry[] = [];
  try {
    const file = opLogPath();
    if (existsSync(file)) {
      for (const line of readFileSync(file, "utf8").split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          entries.push(JSON.parse(trimmed) as OpLogEntry);
        } catch {
          // skip malformed lines
        }
      }
    }
  } catch {
    return [];
  }
  if (filter.category) {
    entries = entries.filter((e) => e.category === filter.category);
  }
  if (filter.target) {
    const t = filter.target;
    entries = entries.filter(
      (e) =>
        e.targetName === t || e.targetName?.startsWith(`${t}/`) || e.url?.includes(t),
    );
  }
  return entries.slice(-(filter.limit ?? 50)).reverse();
}

/** Truncate exec output for the log. */
export function truncateOutput(output: string): { output: string; truncated: boolean } {
  if (output.length <= OUTPUT_LIMIT) return { output, truncated: false };
  return { output: output.slice(0, OUTPUT_LIMIT), truncated: true };
}

/** One-line rendering for `memparty log`. */
export function formatOp(e: OpLogEntry): string {
  const ts = e.ts.replace("T", " ").slice(0, 19);
  const cat = e.category.padEnd(7);
  const status = e.ok ? "ok  " : "FAIL";
  const target = e.targetName ?? e.url ?? "-";
  const ms = e.durationMs !== undefined ? ` (${e.durationMs}ms)` : "";
  let summary: string;
  if (e.category === "exec") {
    const out = (e.output ?? e.error ?? "").split("\n", 1)[0]!;
    const more =
      (e.output ?? "").includes("\n") || e.outputTruncated ? "…" : "";
    summary = `$ ${e.command ?? ""} → ${out}${more}`;
  } else {
    summary = e.detail ?? e.error ?? e.action;
  }
  return `${ts}  ${cat} ${status} ${target}  ${summary}${ms}`;
}
