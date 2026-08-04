/**
 * Interactive REPL for `memparty` with no arguments: one process, many
 * commands. Each line is parsed like regular CLI argv (quotes supported),
 * so anything that works as `memparty <line>` works at the prompt —
 * including `--help` on any subcommand. Built-ins: help, clear, exit/quit.
 *
 * Since connect/exec auto-save verified shells, a typical session is:
 *   connect -u http://host/shell.jsp -t godzilla --header-value XXX
 *   exec host/godzilla --cmd whoami
 */
import * as readline from "node:readline";

import { Command, CommanderError } from "commander";

import { ApiError } from "./api/client.js";
import { reportError } from "./cli-context.js";
import { CLI_VERSION } from "./version.js";

/** Split a REPL line into argv-like tokens, honoring single/double quotes. */
export function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let started = false;
  for (const ch of line) {
    if (quote !== null) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started || cur.length > 0) {
        tokens.push(cur);
        cur = "";
        started = false;
      }
    } else {
      cur += ch;
    }
  }
  if (started || cur.length > 0) tokens.push(cur);
  return tokens;
}

export async function startRepl(build: () => Command): Promise<void> {
  process.stdout.write(
    `memparty ${CLI_VERSION} — interactive mode. Type 'help' for commands, 'exit' to quit.\n`,
  );

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: process.stdin.isTTY === true,
    historySize: 200,
  });

  // Queue lines ourselves: with piped (non-TTY) stdin, readline may buffer
  // several lines at once and drop any emitted while no question is pending.
  const pending: string[] = [];
  let waiter: ((line: string | null) => void) | null = null;
  let closed = false;
  rl.on("line", (line) => {
    if (waiter) {
      const w = waiter;
      waiter = null;
      w(line);
    } else {
      pending.push(line);
    }
  });
  rl.on("close", () => {
    closed = true;
    waiter?.(null);
  });
  const isTty = process.stdin.isTTY === true;
  rl.setPrompt("memparty> ");
  const ask = (): Promise<string | null> => {
    if (isTty) rl.prompt();
    const buffered = pending.shift();
    if (buffered !== undefined) return Promise.resolve(buffered);
    if (closed) return Promise.resolve(null);
    return new Promise((resolve) => {
      waiter = resolve;
    });
  };

  for (;;) {
    const line = await ask();
    if (line === null) break; // EOF / Ctrl-D
    const tokens = tokenize(line);
    if (tokens.length === 0) continue;
    const [cmd, ...rest] = tokens;

    if (cmd === "exit" || cmd === "quit") break;
    if (cmd === "clear") {
      process.stdout.write("[2J[0f");
      continue;
    }
    if (cmd === "help") {
      if (rest.length === 0) {
        build().outputHelp();
        continue;
      }
      tokens.push("--help"); // `help connect` == `connect --help`
    }

    rl.pause(); // let wizards/prompts own stdin while the command runs
    try {
      await build().parseAsync(["node", "memparty", ...tokens]);
    } catch (err) {
      if (err instanceof CommanderError) {
        // exitOverride: commander already printed help or the usage error
      } else if (err instanceof ApiError) {
        reportError(`API error (${err.status || "network"}): ${err.message}`, tokens);
      } else if (err instanceof Error) {
        if (err.name === "ExitPromptError") process.stderr.write("\nAborted.\n");
        else reportError(err.message, tokens);
      } else {
        reportError(String(err), tokens);
      }
    }
    process.exitCode = 0; // a failed command must not poison the REPL's exit status
    rl.resume();
  }

  rl.close();
}
