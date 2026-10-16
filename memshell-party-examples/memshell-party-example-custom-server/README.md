# memshell-party-example-custom-server

演示**怎么给自己的容器/场景写一个 server 插件（注入器）**。扩展面四件套
（server / shelltool / GUI / 自带 shell 字节）里，server 是最难的一个 ——
注入器要碰容器内部，本示例用最小的代码量把这条路走通。

## 思路：应用内注入省掉的是什么

内置 Tomcat 注入器（`TomcatFilterInjector`）从线程堆栈里挖 `StandardContext`
（三种线索全量反射），为的是支持"注入器跑在应用外"（注入代码自身不在 webapp 里
执行）的场景。本示例换一个前提：**注入器永远由应用内的入口执行**（JSP / EL /
表达式注入的入口本来就在 webapp 里），于是找 context 变成两步反射：

1. 应用内 TCCL 就是 webapp ClassLoader（Tomcat 的 `WebappClassLoaderBase` 一族），
   顺着 `resources → getContext()` 拿到 `StandardContext`
   —— 注意 Tomcat **不会**把请求对象放进 thread-local，所以"扫线程找请求"这条路
   对 Tomcat 走不通，这正是内置注入器要挖线程堆栈的原因；
2. 内存马字节用 TCCL（webapp ClassLoader）`defineClass`；
3. 注册与挂载。

**注册部分为什么不能只用公有 API**：Servlet 3.0 的 `ServletContext.addFilter` /
`addServlet` 在 context 初始化后会直接抛
`IllegalStateException: Filters cannot be added ... as the context has been initialised`
—— 内存马注入永远发生在初始化之后，所以必须走 `StandardContext.addFilterDef` +
filterMaps 私有反射（Filter 版）、`addChild(StandardWrapper)` +
`addServletMapping`（Servlet 版）。**这就是内置注入器又长又丑的原因：应用内注入
省掉的只是找 context 那一段（~50 行线程扫描），注册那一段省不掉。**

## 一个 server 插件由什么组成

| 文件 | 作用 |
|---|---|
| `DemoServer` | server 本体（`extends AbstractServer`）：`InjectorMapping` 声明 shellType → 注入器模板类 |
| `DemoFilterInjector` / `DemoServletInjector` | 注入器模板：被投递到目标容器里执行注入的类，生成期只按字节读取 |
| `DemoServerProvider` | SPI 入口：`@MetaInfServices` + `@ServerMeta(name = "DemoServletApp", order = 1000)`，`MemShellRegistry` 靠它发现插件 |

> **模板必须自包含**：生成器只会重命名注入器模板这一个类、把
> `getUrlPattern()` / `getClassName()` / `getBase64String()` 替换成真实值。
> 类里引用的任何外部基类/工具类都不会随注入器一起投递，所以两个注入器各自的
> 辅助方法（反射 / base64 / gzip）是复制进模板的 —— 这不是偷懒，是
> 内置注入器都在用的写法。

## 怎么生成

```java
MemShellResult result = new MemShellGenerator().generate(
        ShellConfig.builder()
                .server(DemoServerProvider.NAME)  // "DemoServletApp"
                .shellTool(ShellTool.Command)     // 内存马模板来自内置 shelltool，注入器来自你的 server
                .shellType(ShellType.FILTER)
                .build(),
        InjectorConfig.builder().urlPattern("/*").build(),
        CommandConfig.builder().paramName("cmd").build());
```

关键点：**shell 模板和注入器模板来自两个方向**。`MemShellRegistry` 把内置
shelltool 的工具映射（"Command 支持哪些 shellType 的 shell 模板"）和你的 server
注入器映射（"我支持哪些 shellType 的注入器"）求交集，交集之外的类型不会对外暴露
（所以 `DemoServer` 不声明 Listener，注册表里就看不到 Listener）。你只写注入器，
shell 侧所有内置工具（Godzilla/Behinder/Suo5/...）自动可用。

## 与内置 Tomcat 注入器的对照

| | 内置 `TomcatFilterInjector` | 本示例 `DemoFilterInjector` |
|---|---|---|
| 注入器执行位置 | 应用外 / 应用内都行 | 必须在应用内（TCCL 是 webapp ClassLoader） |
| 找 context | 线程堆栈挖 `StandardContext`（三种线索全量反射） | TCCL → `resources` → `getContext()`（两步） |
| 注册方式 | `StandardContext.addFilterDef` + filterMaps 反射 | 相同 —— 公有 API 在 context 初始化后被 Tomcat 拒绝，省不掉 |
| 适用容器 | Tomcat 5-10 | Tomcat 7-10（`WebappClassLoaderBase.resources` 结构一致） |
| 代码量 | ~300 行 | ~270 行（省掉线程扫描与多版本 context 定位） |

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-custom-server:test
```

- `DemoServerGenerationTest`：SPI 发现、映射求交集（只有 Filter/Servlet 及其 Jakarta
  变体对外暴露）、Command/Godzilla × 全部映射类型都能生成。
- `DemoServerEmbeddedTomcatTest`：内嵌 Tomcat 里用一个 trigger servlet 模拟应用内
  入口，在请求线程里执行注入器 —— 断言注入器自报 `filter [/*] ready` /
  `servlet [/cmd] ready`，然后 HTTP 驱动两种内存马真正执行命令（各自用不同的触发
  参数，避免 `/*` 上的 Filter 抢先应答），普通请求依旧 404。
