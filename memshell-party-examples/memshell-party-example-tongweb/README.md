# memshell-party-example-tongweb

固定（pin）真实使用方 [TongWebExploit](https://github.com/ReaJason/TongWebExploit) 消费 MemShellParty
的方式，防止 3.x 模块化重构破坏使用方契约。

它演示并测试两种用法：

1. **强类型配置** — `ShellConfig` / `InjectorConfig` / `GodzillaConfig` builder +
   `new MemShellGenerator().generate(...)` 实例调用。
2. **动态参数配置** — `new MemShellGenerator().generate(shellConfig, injectorConfig, Map<String, String>)`，
   适合工具名/参数在运行期才确定的场景（如从 UI 或 CLI 透传）。

## 依赖选择

核心原则：**只引入你要打的目标 server 和你要提供的 shell 工具**，其余一概不引。

```kotlin
dependencies {
    // 生成引擎（传递引入 api + common）
    implementation("io.github.reajason:memshell-party-core:3.0.0")

    // 目标 server —— TongWeb（传递引入其基座 server-tomcat）
    implementation("io.github.reajason:memshell-party-server-tongweb:3.0.0")

    // 你要提供的 shell 工具，每个通过 SPI 自动注册
    implementation("io.github.reajason:memshell-party-shelltool-godzilla:3.0.0")
    implementation("io.github.reajason:memshell-party-shelltool-behinder:3.0.0")
    // ...suo5 / antsword / neoregeorg / command 同理
}
```

## 按 shellType 补充生成期 API 签名包

shell/injector 模板类的父类和接口在生成期以**字节方式**解析（不会加载进 JVM），
因此 ByteBuddy 需要能从 classpath 读到这些父类的 class 文件。按需添加：

| shellType | 需要的生成期依赖 | 体积 |
|---|---|---|
| `Filter` / `Listener` / `Servlet`（含 Jakarta* 变体） | `javax.servlet:javax.servlet-api` | 83 KB |
| `Valve` / `ProxyValve` | `org.apache.tomcat.embed:tomcat-embed-core` | 3.3 MB |
| `Agent*`（AgentFilterChain / AgentContextValve / AgentInterceptor） | 无 | 0 |

这些依赖故意**不是** shelltool/server 模块的传递依赖——否则使用方会被迫 shade
spring、dubbo、reactor 等与自己目标无关的 API（2.x 就是这么膨胀到 ~50MB 的）。

> 打 shade 包时这些 API 签名包只会被 ByteBuddy 读取、不会进入生成的 shell 字节码，
> 但如果你的工具运行时不需要它们，可以用 `compileOnly` + 生成任务单独 classpath，
> 或者直接 shade 后排除——它们对运行期无影响。

## Shade 打包必须合并 SPI 文件

server / shelltool 模块通过 `META-INF/services` 注册。打 fat jar 时**必须**合并，
否则 `MemShellRegistry` 发现不了任何 server/tool：

- Maven Shade：`ServicesResourceTransformer`
- Gradle Shadow：`mergeServiceFiles()`，并且 Shadow 9 还要
  `filesMatching("META-INF/services/**") { duplicatesStrategy = DuplicatesStrategy.INCLUDE }`
  —— 默认 EXCLUDE 会把重复资源在进 transformer 之前丢掉，合并结果只剩一条
  （完整配方见 `memshell-party-examples/memshell-party-example-custom-shelltool-gui` 的 shadowJar 配置）

## 体积实测

本模块的 `runtimeClasspath`（即使用方需要 shade 的全部内容）：

```
./gradlew :memshell-party-examples:memshell-party-example-tongweb:measureRuntimeFootprint
```

| 组成 | 体积 |
|---|---|
| byte-buddy（生成引擎核心） | 4.45 MB |
| commons-io / commons-lang3 / commons-codec | 1.55 MB |
| asm × 3 | 0.24 MB |
| jackson-annotations / jetbrains-annotations | 0.10 MB |
| memshell-party-core + api + common | 0.26 MB |
| memshell-party-server-tongweb(+tomcat) | 0.10 MB |
| memshell-party-shelltool × 7 | 0.54 MB |
| **合计** | **7.33 MB** |

对比 2.x：同样的 TongWeb + 7 工具使用场景被迫 shade spring（16MB）、tomcat-catalina、
javassist 等，TongWebExploit.jar 达 **53.5MB**。3.x 下同场景 **7.33MB（-86%）**，
若只用 Filter/Listener/Servlet 再加 83KB servlet-api 即可。

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-tongweb:test
```

覆盖：SPI 发现（TongWeb + 全部工具）、2.x 强类型调用逐项兼容、Godzilla ×
TongWeb 全部 shellType、动态参数、Suo5 工具发现、Custom 自定义 shell、
injector base64 可直接嵌入 payload。
