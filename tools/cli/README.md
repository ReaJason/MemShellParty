# tools/cli — MemShellParty Node CLI

Standalone **Node.js** client in this monorepo (**not** a Gradle module).

- Talks to the existing HTTP API (`boot` / [party.mem.mk](https://party.mem.mk)): generate memshell & probe shells.
- Same codebase as [7-e1even/memshell-party-cli](https://github.com/7-e1even/memshell-party-cli).
- Related to [#143](https://github.com/ReaJason/MemShellParty/issues/143).

## Build & test (in this monorepo)

```bash
cd tools/cli
npm ci
npm test
npm run build
node dist/cli.js --api http://127.0.0.1:8080 gen
```

Requires Node.js >= 18. Does **not** participate in `./gradlew` or the Docker image (`Dockerfile` / `.dockerignore` already drop `tools/`).

---

# memshell-party-cli

[English](README.en.md) | 中文

[MemShellParty](https://party.mem.mk) 的 AI 工具：让 AI 帮你生成 Java 内存马、连马、执行命令、传文件。

> ⚠️ 仅限授权安全测试与研究。后果自负。

---

## 第 1 步：安装本工具

1. 电脑装好 [Node.js](https://nodejs.org/)（选 LTS，18 或更新）
2. 打开终端，复制粘贴：

```bash
npm install -g memshell-party-cli
```

3. 检查是否成功：

```bash
memparty version
```

能看到版本号就 OK。

---

## 第 2 步：把使用手册教给 AI（Skill）

Skill 是给 AI 看的完整说明书。装好后，AI 会按手册一步步操作，不用你懂技术。

**用 Claude Code 的，执行：**

```bash
memparty skill install --claude
```

**用别的 AI 代理的，执行：**

```bash
memparty skill install
```

**两个都想装：**

```bash
memparty skill install --user --claude
```

装完后**重启一下你的 AI 工具**（关掉再打开），它才会读到新 skill。

以后升级了本工具，再跑一遍上面的安装命令，就能刷新说明书。

---

## 第 3 步：给 AI 接上 MCP（可选，但推荐）

让 AI 能直接调用本工具。在 AI 的 MCP 配置里加上：

```json
{
  "mcpServers": {
    "memshell-party": {
      "command": "npx",
      "args": ["-y", "memshell-party-cli", "mcp"]
    }
  }
}
```

保存后重启 AI。

---

## 第 4 步：直接对 AI 说话

**先确认 skill 在不在（推荐每次新开对话先说这句）：**

```text
请先读取 memshell-party 这个 skill，然后严格按 skill 里的步骤操作，不要自己瞎猜参数。
```

**生成一个马：**

```text
请按 memshell-party skill，帮我生成一个常用的 Tomcat 哥斯拉内存马。
把文件、密码、密钥都给我，并用简单话告诉我下一步怎么做。
```

**连上马并执行命令：**

```text
请按 memshell-party skill 操作。
网址：【http://这里换成你的地址】
类型：哥斯拉，密码：【pass】，密钥：【key】。
先测能不能连上，连上后执行 whoami，用简单话告诉我结果。
```

**传文件：**

```text
请按 memshell-party skill。
在已经连上的马上：
下载服务器上的【/etc/passwd】到本地；
上传本地【工具.exe】到服务器【/tmp/工具.exe】。
```

**我完全不懂，你带我：**

```text
我是小白。请先读取 memshell-party skill，然后一步一步带我：
1. 生成一个常用的 Tomcat 哥斯拉内存马
2. 用大白话告诉我生成结果里哪些要保存
3. 我部署好后把网址发给你，你帮我连上并执行命令
每一步先说明要做什么，等我确认再继续。只在我授权的环境操作。
```

---

## 许可证

MIT
