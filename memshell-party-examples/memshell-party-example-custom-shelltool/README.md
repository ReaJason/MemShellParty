# memshell-party-example-custom-shelltool

演示**如何自己实现一个 shelltool 插件**：照抄内置 Godzilla 的协议，但把 payload（core）从
`private static Class<?> payload` 挪进 `HttpSession`（key 是一个随机名字），于是**每条连接
（每个会话）都会用自己带来的字节重新注入一份 core**，会话结束即释放。

只适配了 servlet-api 相关的 shellType：`Filter`、`Servlet`、`Listener` 及其 Jakarta 变体。

## 一个 shelltool 插件由什么组成

| 文件 | 作用 |
|---|---|
| `GodzillaSessionFilter/Servlet/Listener` | shell 模板：被注入到目标容器里的类，模板本身不参与运行，生成期只按字节读取 |
| `GodzillaSessionConfig` | 工具配置（`extends ShellToolConfig`）：pass/key/header/sessionKey，字段标 `@ConfigField` 后就是对外可配置参数（REST / MCP / GUI 的表单都按它生成） |
| `GodzillaSessionGenerator` | 生成器（`extends ByteBuddyShellGenerator`）：把配置写进模板的静态字段 |
| `GodzillaSessionShellToolProvider` | SPI 入口：`@MetaInfServices` + `@ShellToolMeta(name = "GodzillaSession", order = 1000)`，声明 shellType → 模板类映射 |
| `META-INF/services/...ShellToolProvider` | 由 `@MetaInfServices` 注解处理器生成，`MemShellRegistry` 靠它发现插件 |

内置工具用 `ShellTool` 常量类里的名字；自定义工具自己维护一个常量（这里是
`GodzillaSessionShellToolProvider.NAME`），注册顺序按 `@ShellToolMeta.order` 排（内置 0-999，
插件建议 1000+）。

## payload 为什么要放 session

内置模板（`GodzillaFilter` 等）把 core 缓存在 `private static Class<?> payload`：全进程只认第一个
会话注入的 core。本示例改成会话存储，差别如下：

| | 静态字段（内置） | 会话存储（本示例） |
|---|---|---|
| core 的归属 | 内存马类一份，所有会话共用 | 每个会话各自一份 |
| 换客户端/换 core | 后续连接带来的 core 不生效，除非内存马重新注入 | 新连接（新会话）重新定义自己的 core |
| 生命周期 | 与内存马类同生共死，常驻堆内存 | 客户端 `close`（服务端 `invalidate`）/ 会话过期后随会话释放 |
| 请求要求 | 无 | 同一会话的请求必须带 `JSESSIONID` cookie |

实现上就是每次定义都 `new 模板类(TCCL)` 新建一个 ClassLoader：core 与内存马类隔离，会话之间也
互不影响，即使两次注入的 core 类名相同也不会撞 `LinkageError`。

> 已知限制：会话里存的是 `Class` 对象，不可序列化。容器做 session 持久化/集群复制
> （Tomcat 关停时的 `SESSIONS.ser`、会话共享）时该属性会被丢弃；需要这类场景就用静态字段版本。

> **模板是快照副本**：`GodzillaSessionFilter/Servlet/Listener` 是内置 Godzilla 模板的
> 快照（协议逻辑逐字节同源，只有 payload 存放位置不同），协议演进（混淆、修复）时需手动
> 同步这三份。CI 里的 `GodzillaSessionEmbeddedTomcatTest` 用真实哥斯拉客户端跑协议，
> 是防止漂移静默腐烂的唯一保险丝。

## 怎么生成

```java
// 强类型写法
MemShellResult result = new MemShellGenerator().generate(
        ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(GodzillaSessionShellToolProvider.NAME) // "GodzillaSession"
                .shellType(ShellType.FILTER)
                .build(),
        InjectorConfig.builder().urlPattern("/*").build(),
        GodzillaSessionConfig.builder()
                .pass("pass")
                .key("key")
                .headerValue("Firefox")  // 客户端 UA 里含这个子串才会命中
                .build());
// result.getInjectorBytes() 投入任意入口执行即完成注入；result.getShellBytes() 是内存马本体
```

```java
// 动态参数写法（GUI / REST / MCP 走这条）：参数名就是 config 的字段名，不带工具前缀
Map<String, String> params = new HashMap<>();
params.put("pass", "pass");
params.put("key", "key");
params.put("sessionKey", "sessionCore");
new MemShellGenerator().generate(shellConfig, injectorConfig, params);
// 留空的参数走随机默认值；写了 config 里不存在的参数名（如 godzillaSessionPass）会直接抛 GenerationException
```

客户端（哥斯拉）只需要：UA/自定义头带上 `headerValue`、POST 参数名是 `pass`、AES key 是
`md5(key)[0:16]` —— 与内置 Godzilla 完全一致，**但必须保持同一个会话**（哥斯拉客户端会自动带
第一次响应里的 `JSESSIONID`，不要禁用 cookie）。要是每次请求都换会话，内存马每次都在定义新 core，
看起来就像"命令没回显"。

## 换到别的容器 / 扩展 shellType

- 换容器：生成时指定 `server` 即可（模板只依赖 servlet-api，容器相关的部分由 server 模块的注入器
  负责）。自定义工具不需要自己的注入器。
- 加类型：写模板类 → 在 `getToolMapping()` 里加一行映射。`MemShellRegistry` 会把它和目标 server
  的注入器映射求交集，server 没有对应注入器的类型不会对外暴露（所以这里不需要判断 server）。
- Jakarta 变体复用同一份 javax 模板，生成期由 `JakartaPostProcessor` 改名。

## 打包装进自己的工具时注意

- shelltool 模块通过 `META-INF/services` 注册：Maven Shade 用 `ServicesResourceTransformer`；
  Gradle Shadow 除了 `mergeServiceFiles()` 还要
  `filesMatching("META-INF/services/**") { duplicatesStrategy = DuplicatesStrategy.INCLUDE }`
  （Shadow 9 默认 EXCLUDE，重复资源在进 transformer 之前就被丢掉，merge 只看到一份拷贝）。
  完整配方与验证见 `memshell-party-examples/memshell-party-example-custom-shelltool-gui` 的 shadowJar 配置
  和 `FatJarServiceDiscoveryTest`。
- 生成期需要目标类型的 API 签名包（本示例的 `Filter/Servlet/Listener` 需要 `javax.servlet-api`；
  Jakarta 变体还需要 `jakarta.servlet-api`），它们只被 ByteBuddy 读字节码、不会进生成的 shell，
  也不需要作为传递依赖带给使用方（所以本模块用 `compileOnly`）。
- 想把这个工具接进桌面 GUI（专用参数面板、自己的品牌、结果动作）：见
  `memshell-party-examples/memshell-party-example-custom-shelltool-gui`；什么都不做的话，插件默认也会出现在
  GUI 的工具下拉框里，参数面板按 config 类上的 `@ConfigField` 注解生成。

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-custom-shelltool:test
```

- `GodzillaSessionShellToolProviderTest`：SPI 注册、只暴露 servlet-api 类型、6 个 shellType 都能生成、
  字段被写入、**生成的类里没有 payload 静态字段**、Jakarta 改名、动态参数绑定，
  以及在 Tomcat 之外的 servlet 容器（示例里是 Undertow）上同样能生成。
- `GodzillaSessionEmbeddedTomcatTest`：起内嵌 Tomcat，用真实的哥斯拉协议客户端连上去，逐条验证
  会话行为 —— 注入前会话里没有 core；第一条连接注入后 core 出现在会话里且与内存马类隔离；
  同会话的后续请求命中会话里的 core；第二条连接重新注入一份互不影响；客户端 `close` 后 core 随
  会话释放。
