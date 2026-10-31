# memshell-party-example-custom-gui

演示**下游怎么把自己的扩展装进 MemShellParty**，一个模块覆盖四个 SPI 扩展面：

| 扩展面 | 入口 | 本示例的实现 |
|---|---|---|
| server 插件（注入器） | `ServerProvider` + `@ServerMeta` | `DemoServer`：应用内注入，支持 Filter/Servlet 及其 Jakarta 变体 |
| shelltool 插件 | `ShellToolProvider` + `@ShellToolMeta` | `GodzillaSessionExample`：哥斯拉协议不变，core 从静态字段挪进 `HttpSession` |
| packer 插件 | `Packer` + `@PackerMeta` | `GzipBase64URL`：gzip + URL-safe Base64，适合 URL/Header 传输 |
| GUI 扩展 | `GuiExtension` | 专用参数面板、品牌、结果区动作、生成成功回调 |

四块拼图装进同一个可运行的桌面程序：服务端、工具、打包方式三个下拉框里，内置项与自定义项同时存在。
`sdk` 只提供界面框架，server/shelltool/packer 由宿主按需自引；本模块只引了 Tomcat 与内置 Godzilla。

## 目录

| 路径 | 内容 |
|---|---|
| `CustomGuiApplication` | 入口：FlatLaf + 自建外壳 + SPI 自动发现扩展 |
| `gui/` | `CustomGuiFrame`（自建外壳）、`GodzillaSessionGuiExtension`（扩展点）、`GodzillaSessionToolPanel`（专用面板）、`ShellLedger` / `AddToShellLedgerAction`（结果落到下游台账） |
| `server/` | `DemoServer`、`DemoFilterInjector` / `DemoServletInjector`、`DemoServerProvider` |
| `shelltool/` | `GodzillaSessionFilter/Servlet/Listener`、`GodzillaSessionConfig`、`GodzillaSessionGenerator`、`GodzillaSessionShellToolProvider` |
| `packer/` | `GzipBase64URLPacker` |

## 运行

```
./gradlew :memshell-party-examples:memshell-party-example-custom-gui:run
```

窗口属性、页签、状态栏都是宿主自己的（`CustomGuiFrame`）：SDK 只给两个生成器 frame
（`MemShellGeneratorFrame` / `ProbeGeneratorFrame`），`getRootPanel()` 取界面本体、
`setStatusReporter(...)` 接状态出口、`installGenerateShortcut(...)` 挂 Ctrl/⌘ + Enter。
接进已有客户端时按这三步组装即可。

## 自定义 server：应用内注入

内置 Tomcat 注入器从线程堆栈里挖 `StandardContext`，支持"注入器跑在应用外"。本示例换了前提：
注入器永远由应用内入口（JSP / EL / 表达式注入）执行，TCCL 就是 webapp ClassLoader，
顺着 `resources → getContext()` 两步拿到 `StandardContext`。

**注册部分不能只用公有 API**：Servlet 3.0 的 `ServletContext.addFilter` / `addServlet` 在
context 初始化后会抛 `IllegalStateException`，而内存马注入永远发生在初始化之后，所以
`addFilterDef` + `filterMaps`（Filter）、`addChild(StandardWrapper)` + `addServletMapping`
（Servlet）的私有反射省不掉 —— 应用内注入省掉的只是找 context 那一段。

`DemoServer` 只声明了 Filter/Servlet 及相关 Jakarta 变体；`MemShellRegistry` 会把 server 的
注入器映射与工具的 shellType 映射求交集，没有注入器的类型不会对外暴露。你只写注入器，
shell 侧所有内置工具（Godzilla/Command/...）自动可用。

> **模板必须自包含**：生成器只重命名注入器模板这一个类、替换 `getUrlPattern()` /
> `getClassName()` / `getBase64String()`。模板引用的外部基类/工具类不会随注入器一起投递，
> 所以反射 / base64 / gzip 这些辅助方法都复制进了模板。

## 自定义 shelltool：core 放进会话

协议与内置 Godzilla 完全一致（pass/key/UA/AES），差别只有 payload（core）的存放位置：
内置模板用 `private static Class<?> payload`，全进程共用；本示例放进当前 `HttpSession`
（key 是生成期写入的随机 `sessionKey`），于是每条连接都定义自己的 core，会话过期即释放。

实现上每次定义都 `new 模板类(TCCL)` 新建一个 ClassLoader：core 与内存马类隔离，会话之间
互不影响，同名 core 也不会撞 `LinkageError`。已知限制：会话里存的是 `Class` 对象，不可序列化，
容器做 session 持久化/集群复制时该属性会被丢弃。

> 会话版哥斯拉已作为内置工具 `GodzillaSession` 落地（issue #159），所以示例工具名改为
> `GodzillaSessionExample` 只作 SPI 教学 —— 工具名不能与内置重名，同名注册会被静默忽略。

## 自定义 packer：新的投递编码

打包器只处理后置编码：注入器字节不变，只改变「怎么把字节送到目标」。本示例把注入器字节
gzip 后做 URL-safe Base64（无 padding），输出可以直接放进 URL 参数、Header 或 Cookie。

```java
@MetaInfServices(Packer.class)
@PackerMeta(name = GzipBase64URLPacker.NAME, parent = Packers.Base64, order = 10000)
public class GzipBase64URLPacker implements Packer {
    public String pack(ClassPackerConfig config) { ... }
}
```

`parent` 只决定界面里的分组（这里挂到内置的 `Base64` 分组下，不要求存在同名 packer）；
内置项用 100 起的 order，第三方默认 10000 排在末尾。`@MetaInfServices` 生成的
`META-INF/services/com.reajason.javaweb.packer.Packer` 由 `PackerRegistry` 通过
ServiceLoader 发现，GUI / REST / MCP 三端共用这份目录。

## 生成方式

强类型写法（自定义 server + 自定义工具 + 内置 packer）：

```java
MemShellResult result = new MemShellGenerator().generate(
        ShellConfig.builder()
                .server(DemoServerProvider.NAME)        // "DemoServletApp"
                .shellTool(GodzillaSessionShellToolProvider.NAME)
                .shellType(ShellType.FILTER)
                .build(),
        InjectorConfig.builder().urlPattern("/*").build(),
        GodzillaSessionConfig.builder().pass("pass").key("key").headerValue("Firefox").build());
```

动态参数写法（GUI / REST / MCP 都走这条）：参数名就是工具 config 的 `@ConfigField` 字段名，
留空走随机默认值，写了不存在的参数名会抛 `GenerationException`。
自定义 packer 通过 `PackerRegistry.pack(name, result)` 或 GUI 的「打包方式」选择生效。

## GUI 扩展点（`GuiExtension`）

| 方法 | 作用 |
|---|---|
| `name()` | 扩展名（按名字去重） |
| `applicationTitle(default)` | 生成器窗口标题 |
| `toolPanels()` | 工具名 → 专用面板工厂（不实现则按 `@ConfigField` 自动生成） |
| `resultActions()` | 结果区动作按钮（无结果时自动置灰） |
| `onResultGenerated(result)` | 生成成功回调（EDT 上执行） |

`GodzillaSessionToolPanel` 继承 `AbstractToolPanel` 即自带「挂载类型 + 请求路径」公共字段；
参数读写走 `controller.setToolParam(name, value)`，和动态面板同一条链路
（`toolParams → config 字段 → 生成期写进内存马字段`），专用面板只改变外观。

## 打包与发布

- 发行物是 `shadowJar`：`memshell-party-custom-gui-<version>.jar`，`java -jar` 直接运行，
  随 GitHub Release 发布（`.github/workflows/release.yaml`）。
- 四类 SPI 文件必须合并（`mergeServiceFiles()`），且 Shadow 9 的 `duplicatesStrategy`
  默认 `EXCLUDE`，重复资源在进 transformer 前就被丢掉 —— 必须对 `META-INF/services/**`
  放开去重，否则合并结果只剩一条，构建却不报错。完整配方见本模块 `build.gradle.kts`，
  `FatJarServiceDiscoveryTest` 直接开包断言四类 SPI 的合并结果。
- 测试内嵌真 Tomcat：`server-tomcat` 传递的桩与 `tomcat-embed-core` 同包名，
  已在 `testRuntimeClasspath` 排除桩，示例本身仍靠桩生成 Tomcat 的 Valve/WebSocket 类型。

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-custom-gui:test
```

- `DemoServerGenerationTest`：自定义 server 的 SPI 发现、映射求交集、Command/Godzilla 生成。
- `DemoServerEmbeddedTomcatTest`：内嵌 Tomcat 里从请求线程执行注入器，HTTP 驱动两种内存马。
- `GodzillaSessionShellToolProviderTest`：工具 SPI、servlet-api 类型、字段写入、Jakarta 改名、
  动态参数绑定；换容器（Undertow）同样能生成。
- `GodzillaSessionEmbeddedTomcatTest`：真实哥斯拉客户端验证 core 跟会话走、按连接隔离、随会话释放。
- `CustomPackerTest`：packer SPI 发现与分组、URL-safe 输出，以及 GUI 生成链路能还原注入器字节。
- `GodzillaSessionGuiExtensionTest`：扩展 SPI 发现、专用面板接管、结果回调/动作落台账。
- `CustomGuiFrameTest`（需要显示环境，headless 跳过）：宿主外壳与 SDK 生成器的接线。
- `FatJarServiceDiscoveryTest`：fat jar 里四类 SPI 的合并结果。
