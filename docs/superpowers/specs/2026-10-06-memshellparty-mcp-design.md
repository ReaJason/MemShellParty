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
| `boot/.../mcp/MemShellMcpTools.java` | `@McpTool` 三个方法：入参 → Service → 结果整形 |
| `boot/.../mcp/McpPayloadWriter.java` | 落盘、SHA256、文件名生成、路径穿越防护 |
| `boot/.../config/McpSecurityConfig.java` | Bearer 校验 + 非本机访问拦截 |

两个 Controller 变为薄壳：接 DTO → 调 Service → 返回。其现有测试是重构的回归基线，必须原样通过。

## 5. 工具契约

### `list_support_matrix`

无参数。返回合并后的能力矩阵——生成前查询的唯一能力来源。

```json
{
  "servers": { "Tomcat": { "Godzilla": ["Filter", "Servlet", "Listener"], "...": [] } },
  "packers": [ { "name": "Base64", "children": ["Base64"] } ],
  "commandConfigs": { "encryptors": [], "implementationClasses": [] }
}
```

### `generate_memshell`

| 分组 | 参数 |
|---|---|
| 目标三元组 | `server`\* `shellTool`\* `shellType`\* `serverVersion` |
| 生成开关 | `targetJreVersion`(默认 6) `byPassJavaModule` `shrink` `lambdaSuffix` `jakarta` `probe` |
| 工具专属 | `pass` `key` `headerName` `headerValue` `paramName` `template` `encryptor` `implementationClass` `shellClassBase64` |
| 打包与输出 | `packer`(默认 `Base64`) `output`(默认 `metadata`) `filename` |

### `generate_probe`

`server`\* `shellType`\* `probeMethod`\*(DNSLog/Sleep/ResponseBody) + `host` / `seconds` / `reqParamName` / `commandTemplate`，其余同 `generate_memshell`。

### 统一返回值

```json
{
  "shellClassName": "...", "shellSize": 8123,
  "injectorClassName": "...", "injectorSize": 4512,
  "packer": "Base64",
  "files": [ { "path": "...", "sha256": "...", "bytes": 11000 } ],
  "warnings": []
}
```

`output` 三态：`metadata`（只落盘） / `base64`（只内联 `content`） / `both`。

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
