# MemShellParty MCP Server 设计

日期：2026-10-06
状态：已批准

## 1. 目标

在现有 `boot` 模块（Spring Boot 4.1.0）中集成 MCP Server，使 AI Agent 能够通过 MCP 协议调用 MemShellParty 的内存马生成能力。

一份制品、一个进程同时提供两种接口：

- REST `/api/*` —— 供现有 `web` 前端使用（行为零改动）
- MCP `POST /mcp` —— 供 Claude Code 等 MCP 客户端使用（Streamable HTTP）

## 2. 决策记录

| 决策点 | 选择 | 理由 |
|---|---|---|
| 形态 | 集成进 `boot`（Spring AI MCP） | 单一制品，复用现有生成逻辑与部署方式 |
| 传输 | Streamable HTTP | 与 REST 共享 Tomcat，真正一份制品；STDIO 与 REST 互斥 |
| 工具粒度 | 3 工具分层 | 参数矩阵太大无法静态表达，改为「先查矩阵再生成」 |
| 载荷输出 | 默认落盘返回路径 | 避免 5–40KB base64 污染模型上下文；模型对长 base64 无可用性 |
| 安全默认 | 默认关闭 + 可选 Bearer | 零回归，默认最安全 |
| 代码组织 | 抽共享 Service | HTTP 与 MCP 共享生成逻辑，两种入口解耦 |

## 3. 依赖

```toml
# gradle/libs.versions.toml
spring-ai = "2.0.1"
spring-ai-bom = { module = "org.springframework.ai:spring-ai-bom", version.ref = "spring-ai" }
spring-ai-starter-mcp-server-webmvc = { module = "org.springframework.ai:spring-ai-starter-mcp-server-webmvc", version.ref = "spring-ai" }
```

Spring AI 2.0.x 面向 Spring Boot 4.0/4.1 + Spring Framework 7.0，与 `boot` 的 Spring Boot 4.1.0 匹配。`boot` 是 servlet 栈，故使用 `-webmvc` 变体而非 `-webflux`。

## 4. 组件

新增 6 个类，改动 2 个现有 Controller。

| 文件 | 职责 |
|---|---|
| `boot/.../service/MemShellGenerationService.java` | 抽自 `MemShellGeneratorController`。含 `AggregatePacker` → `packAll` / `JarPacker` → Base64 / 其他 → `pack` 三路分支。唯一的生成入口 |
| `boot/.../service/ProbeGenerationService.java` | 抽自 `ProbeShellGeneratorController`，结构同上 |
| `boot/.../service/SupportMatrixService.java` | 抽自 `ConfigController` 的 `config()` / `getPackerTree()` / `getCommandConfigs()` |
| `boot/.../service/ShellToolConfigMapper.java` | shellTool → `ShellToolConfig` 的映射，REST 与 MCP 共用一份 |
| `boot/.../service/ProbeContentConfigMapper.java` | probeMethod → `ProbeContentConfig` 的映射，同上 |
| `boot/.../mcp/MemShellMcpTools.java` | `@McpTool` 三个方法：入参 → Service → 结果整形 |
| `boot/.../mcp/McpPayloadWriter.java` | 落盘、SHA256、文件名生成、路径穿越防护 |
| `boot/.../config/McpConfiguration.java` | Bean 装配，整体受 `spring.ai.mcp.server.enabled` 门控 |
| `boot/.../config/McpAccessFilter.java` | Bearer 校验 + 非本机访问拦截 |

`ShellToolConfigMapper` / `ProbeContentConfigMapper` 是实装期补的：原先这两段 switch 写在 HTTP DTO
（`MemShellGenerateRequest.parseShellToolConfig()` / `ProbeShellGenerateRequest.parseProbeContentConfig()`）里，
MCP 若复制一份就会随 shellTool 增加而漂移。抽为共享映射后，DTO 与 MCP 都委托同一份实现，
HTTP 的 JSON 契约未受影响。

两个 Controller 变为薄壳：接 DTO → 调 Service → 返回。其现有测试是重构的回归基线，必须原样通过。

## 5. 工具契约

### `list_support_matrix`

无参数。返回合并后的能力矩阵——生成前查询的唯一能力来源。

```json
{
  "servers": { "Tomcat": { "Godzilla": ["Filter", "Servlet", "Listener"], "...": [] } },
  "packers": [ { "name": "Base64", "children": ["DefaultBase64", "Base64URLEncoded", "GzipBase64"] } ],
  "commandConfigs": { "encryptors": [], "implementationClasses": [] },
  "probeResponseBodyServers": [],
  "probeMethods": ["DNSLog", "ResponseBody", "Sleep"],
  "probeContents": [],
  "probeContentsByMethod": {
    "DNSLog": ["Server", "JDK"],
    "Sleep": ["Server"],
    "ResponseBody": ["Command", "Bytecode", "Filter", "ScriptEngine"]
  }
}
```

`probeContentsByMethod` 是实装期新增的：`probeContent` 的合法取值随 `probeMethod` 分叉，
生成器未提供内省接口，不显式暴露则调用方只能靠试错。

### `generate_memshell`

| 分组 | 参数 |
|---|---|
| 目标三元组 | `server`\* `shellTool`\* `shellType`\* `serverVersion` |
| 生成开关 | `targetJreVersion`(默认 50) `byPassJavaModule` `debug` `shrink` `lambdaSuffix` `jakarta` `probe` |
| 工具专属 | `pass` `key` `headerName` `headerValue` `paramName` `template` `encryptor` `implementationClass` `shellClassBase64` |
| 注入器 | `urlPattern` `injectorClassName` |
| 打包与输出 | `packer`(默认 `Base64`) `output`(默认 `metadata`) `filename` |

`pass` 是 Godzilla / Behinder / AntSword 的共用参数（REST 契约里是三个独立字段，
MCP 侧只暴露一个并同值填充三个——只有对应 `shellTool` 会消费它，故安全）。

### `generate_probe`

`probeMethod`\*(DNSLog/Sleep/ResponseBody) `server` `host` `seconds` `reqParamName`
`commandTemplate` `probeContent` + 生成开关 + 打包与输出参数。

**修正**：初稿写的 `server`\* `shellType`\* 是错的。探测马没有 `shellType` 概念——
`server` 承载在 `ProbeContentConfig`（`ResponseBodyConfig` / `SleepConfig`）上，一项即可确定注入点。
`probeContent` 也**没有统一默认值**，按 `probeMethod` 分叉：DNSLog/Sleep → `Server`，ResponseBody → `Command`。

### 统一返回值

```json
{
  "kind": "memshell",
  "shellClassName": "...", "shellSize": 8123,
  "injectorClassName": "...", "injectorSize": 4512,
  "packer": "Base64",
  "files": [ { "path": "...", "sha256": "...", "bytes": 11000 } ],
  "content": null,
  "contents": null,
  "warnings": []
}
```

`output` 三态：`metadata`（只落盘） / `base64`（只内联） / `both`。

**修正**：初稿只有 `content` 一个内联字段，实装时发现聚合打包器的多份载荷无法压进单个字符串，
且会导致「聚合 + `output=base64`」时既无文件也无内容。故新增 `contents`（键为打包器名）承载聚合结果。

**返回体绝不回显 `shellToolConfig`**——它含 Godzilla 的 `pass` / `key`，回显等于把密钥写入模型上下文与日志。

## 6. 落盘规则

```
AggregatePacker  -> N 个文件，写入子目录
                    {ts}-{server}-{shellTool}-{shellType}/{packerName}
JarPacker / 其他 -> 单文件 {ts}-{server}-{shellTool}-{shellType}.{jar|b64}
```

- 文件名由服务端生成；`filename` 参数只取 basename，过滤 `/` `\` `..`。不接受用户提供的目录。
- 输出目录 `memshell.mcp.output-dir`，默认 `./memshell-output`，启动时 `Files.createDirectories`。
- Docker 部署需 `-v ./out:/app/memshell-output` 才能看到产物。

## 7. 配置

```yaml
spring:
  ai:
    mcp:
      server:
        enabled: \${MEMSHELL_MCP_ENABLED:false}
        name: memshell-party
        version: ${version}
        protocol: STREAMABLE
        path: /mcp
memshell:
  mcp:
    token: \${MEMSHELL_MCP_TOKEN:}
    output-dir: \${MEMSHELL_MCP_OUTPUT_DIR:./memshell-output}
```

**`\${...}` 的转义是必须的**：`boot/build.gradle.kts` 中 `tasks.processResources { filesMatching("**/application.yaml") { expand(project.properties) } }` 会在构建期先用 Groovy 模板引擎处理 `application.yaml`。未转义的 `\${MEMSHELL_MCP_ENABLED:false}` 会被当作 Groovy 表达式求值，导致 `:boot:bootjar` 构建失败。转义后运行期才由 Spring 解析。`${version}` 不转义，用于注入项目版本号。

## 8. 安全

`McpSecurityConfig` 的 `OncePerRequestFilter` 判定顺序：

1. 路径不匹配 `/mcp` → 放行
2. `memshell.mcp.token` 非空 → 校验 `Authorization: Bearer <token>`，失败 401
3. `token` 为空 → 仅允许 `127.0.0.1` / `::1` / 容器内网段，其余 403 并记 WARN

不引入 `mcp-security` 社区模块，自行实现（约 40 行，避免额外依赖）。

## 9. 测试

| 层 | 方式 |
|---|---|
| Service 层 | 纯单测，mock `MemShellGenerator`。迁移现有 Controller 测试断言，证明重构等价 |
| Tool 层 | 直接 `new MemShellMcpTools(...)` 调方法，断言返回 POJO。不启传输 |
| 落盘 | `@TempDir`，含路径穿越用例（`filename="../../etc/passwd"` 必须被净化） |
| 端到端 | `@SpringBootTest(RANDOM_PORT)` + `McpSyncClient` over `/mcp`，覆盖 `tools/list` 与 `tools/call` |
| 安全 | MockMvc：无 token 非本机 → 403；错误 token → 401；正确 token → 200 |
| 回归 | `./gradlew :boot:test` 全绿 = 重构未破坏 REST |

## 10. 非目标

- 不实现「把载荷投递到目标」——MemShellParty 是生成器，不含利用能力
- 不实现探测结果分析（DNSLog 回显 → 服务类型判定）
- 不改 `generator` / `packer` / `web` 任一模块
- 不做 STDIO 传输（与 REST 互斥）
- 不引入 `mcp-security` 社区模块
- 不为工具声明 outputSchema（载荷以 text content 的 JSON 字符串返回。声明 outputSchema 后
  必须同时产出 `structuredContent`，而嵌套 Map/Set 的 schema 生成有风险，收益不足）

## 11. 实现期修正与补充

以下为设计评审后、实装过程中发现并修正的问题，记录下来避免后续重复踩坑。

### 11.1 编译期：`-parameters` 是必需的

Spring AI 从 `Method.getParameters()` 反射生成 JSON Schema。JDK 默认不保留参数名，
`boot` 原先未开启该选项，会导致工具 schema 退化为 `arg0` / `arg1`——**编译通过、单测通过，但工具对模型完全不可用**。
已在 `boot/build.gradle.kts` 加上：

```kotlin
tasks.withType<JavaCompile>().configureEach { options.compilerArgs.add("-parameters") }
```

该失效模式只能由走真实 MCP 协议的端到端测试兜住，故 `MemShellMcpEndToEndTest` 是必需层而非锦上添花。

### 11.2 构建期：application.yaml 中任何未转义的 `${` 都会中断构建

`boot/build.gradle.kts` 的 `expand(project.properties)` 会用 Groovy `SimpleTemplateEngine`
预解析 `application.yaml`。除 `${version}` 外所有占位符都必须写成 `\${...}`。
**包括注释和文档字符串**——实装时正是在注释里写了一个未转义的 `${...}` 示例而导致构建失败，
报错却指向文件第 1 行，定位成本很高。

### 11.3 部署期：Dockerfile 需预建输出目录

`WORKDIR /app` 由 root 创建，进程以 `spring` 用户运行，因此 `spring` 无法在 `/app` 下创建目录——
开启 MCP 后落盘会 `permission denied`。已在 Dockerfile 中补：

```dockerfile
RUN mkdir -p /app/memshell-output && chown spring:spring /app/memshell-output
ENV MEMSHELL_MCP_OUTPUT_DIR=/app/memshell-output
```

### 11.4 默认打包器是聚合打包器

`Packers.Base64` 对应的 `Base64Packer` 实现了 `AggregatePacker`，
会展开为 `DefaultBase64` / `Base64URLEncoded` / `GzipBase64` 三份输出。
因此默认参数下会写出 3 个文件而非 1 个（REST API 行为一致）。
需要单份载荷时应显式指定单打包器（如 `BigInteger`、`BCEL`）。

## 12. 能力覆盖审计

初版实现后做了一次逐项审计，对照 `web` 前端实际消费的 8 个端点：

| 端点 | MCP 覆盖 |
|---|---|
| `GET /api/config` | ✅ `list_support_matrix.servers` |
| `GET /api/config/packers/tree` | ✅ `.packers` |
| `GET /api/config/command/configs` | ✅ `.commandConfigs` |
| `GET /api/config/probe/response-body/servers` | ✅ `.probeResponseBodyServers` |
| `POST /api/memshell/generate` | ✅ `generate_memshell` |
| `POST /api/probe/generate` | ✅ `generate_probe` |
| `POST /api/className` | ✅ 补齐为 `parse_class_name` |
| `GET /api/version` | ❌ 有意不暴露（见下） |

`/api/config/servers` 与 `/api/config/packers` 两个 deprecated 端点前端已不使用，不计入。

### 12.1 补齐的两项

**`parse_class_name`**：Custom 内存马工作流是「提供 class 字节码 → 解析出全限定类名 → 带着它生成」。
缺少这一步，`shellTool=Custom` 在 MCP 上无法闭环——调用方只持有 Base64 字节码，
拿不到 `shellClassName`。同时把 `ClassNameParseController` 的 3 行逻辑抽成
`ClassNameParseService`，REST 与 MCP 共用。

**`staticInitialize`**：`generate_memshell` 初版漏掉了这个参数（`generate_probe` 有）。
这类遗漏在端点级对照中完全看不出来——只有把**表单字段**逐条比对参数表才会暴露。
测试用「开关该参数后产物 SHA-256 必须改变」来钉住它，防止再次静默失效。

### 12.2 有意不暴露 `/api/version`

该端点会外呼 `api.github.com` 查询最新 release（失败时还会重试镜像源）。
对 AI Agent 而言价值很低，却等于开了一条出网路径——内网与红队场景下未必希望如此。
如需版本信息，MCP 的 `initialize` 响应里已带 `serverInfo.version`。
