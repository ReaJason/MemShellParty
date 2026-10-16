# memshell-party-example-custom-shelltool-gui

演示**自带 shelltool 的下游工具怎么复用 MemShellParty 的桌面界面**，而不是自己从零写一套 Swing 生成器
（dandelion-client 那种客户端就是典型场景：自己的工具 + 自己的界面）。

这个示例做三件事：

1. 自己的 shelltool 仍是上一个示例的插件（`GodzillaSession`），**以 jar 形式接入**，界面通过 SPI 自动发现它 ——
   工具下拉框里直接出现，不需要动界面代码；
2. 不想用反射生成的通用面板：用 `GuiExtension.toolPanels()` 给自己的工具挂**专用参数面板**；
3. 自己的外壳：SDK 只给生成器界面（frame），页签 / 状态栏 / 品牌都是宿主自己的 ——
   见本示例的 `CustomShellFrame`；再配上结果区动作按钮（"加入我的 Shell 列表"）与
   生成成功回调（自动进"生成历史"）。

## 拿 frame 拼自己的窗口

```java
// 自己的外壳（CustomShellFrame）：窗口属性、页签、状态栏都是宿主的
MemShellGui.setupLookAndFeel();                                  // 或换成自己的主题
MemShellGeneratorFrame memShell = new MemShellGeneratorFrame(MemShellGui.resolveExtensions(), false);
ProbeGeneratorFrame probe = new ProbeGeneratorFrame(false);
myTabs.addTab("内存马", memShell.getRootPanel());
myTabs.addTab("探测马", probe.getRootPanel());
memShell.setStatusReporter(myStatusBar::setStatus);              // 状态消息出口
memShell.installGenerateShortcut(getRootPane());                 // Ctrl/⌘ + Enter + 默认按钮（切页时转移）
```

只要一个生成器、独立窗口跑：

```java
MemShellGui.createMemShellFrame(extension).setVisible(true);     // 自带窗口属性与快捷键
```

本仓库里直接跑：

```
./gradlew :memshell-party-examples:memshell-party-example-custom-shelltool-gui:run
```

## 扩展点一览（`GuiExtension`）

| 方法 | 作用 | 不实现时 |
|---|---|---|
| `name()` | 扩展名（按名字去重） | 必填 |
| `applicationTitle(default)` | 生成器窗口标题 | `MemShellParty v2.11.0` |
| `toolPanels()` | 工具名 → 面板工厂（可覆盖内置面板） | 注解生成的动态参数面板 |
| `resultActions()` | 结果区动作按钮（无结果时自动置灰） | 没有按钮 |
| `onResultGenerated(result)` | 生成成功回调（EDT 上执行，抛异常只影响状态出口） | 不回调 |

两种接入方式，可同时用：`@MetaInfServices(GuiExtension.class)` 写进
`META-INF/services`（`MemShellGui.resolveExtensions()` 自动发现），或者显式传入
（`new GodzillaSessionGuiExtension()`，同名时显式传入优先）。

### 专用面板怎么写

`GodzillaSessionToolPanel` 继承 `AbstractToolPanel`（自带"内存马挂载类型 + 请求路径"两个公共字段，
外观和内置面板一致），参数读写走 `controller.setToolParam(name, value)`（key 即 config 字段名）：

```java
public class GodzillaSessionToolPanel extends AbstractToolPanel {
    public GodzillaSessionToolPanel(ToolPanelContext context) {
        super(context.getController(), context.getRefreshAll());
        add(labeled("密码", passField), "growx");
        ...
        bindText(passField, v -> controller.setToolParam("pass", v));
    }
}
```

写的还是 `state.toolParams`，和动态面板**同一条链路**：
`toolParams → 工具的 config 字段（`@ConfigField`）→ 生成期写进内存马静态字段`。所以专用面板只是"长得更好看/更像自己
的产品"，不改变生成逻辑。

## 只写插件行不行？

行。什么扩展都不加，插件工具也会出现在工具下拉框里，参数面板按 config 类上的 `@ConfigField`
注解自动生成（`DynamicToolPanel`），结果区反射展示配置项 —— 一行界面代码都不用写。
需要专用面板、品牌、结果落到自己的数据结构时，才加 `GuiExtension`。

## 依赖与发布状态

两个 GUI 模块分工：`memshell-party-gui-sdk` 是**可扩展 SDK**（两个生成器 frame + 扩展点，不带任何 server，
发布到 Maven Central），`memshell-party-gui-app` 是**完整发行版**（SDK + 官方外壳 + `server-all` + `shelltool-all`
的全量 fat jar）。本示例演示下游客户端的做法：引 SDK，自己挑 server、自己排外壳。

- 仓库内使用：`api(project(":memshell-party-gui:memshell-party-gui-sdk"))`；外部用
  `io.github.reajason:memshell-party-gui-sdk:<version>`（SDK 以 `api` 暴露 core，扩展代码直接就能编译到
  `MemShellResult`、`ShellToolConfig`、`ShellTool` 这些类型）。
- server 不随 SDK 走：本示例只引了 `memshell-party-server-tomcat`，想要全部换成 `memshell-party-server-all`。
  一个都不引也能起窗口，但工具下拉框是空的（列表 = server 注入器映射 × 工具声明求交集）。
- 扩展代码本身可以只依赖 Java 8 API（本模块用 `options.release = 8` 做编译期校验），
  界面跑在 JDK 17 上（FlatLaf/HiDPI/字形渲染）。
- 打包装进自己的客户端时：Shadow 用 `mergeServiceFiles()`，要合并 `ShellToolProvider`
  与 `GuiExtension` 两个 SPI 文件；Shadow 9 的 `duplicatesStrategy` 默认值会把重复文件在进 transformer
  之前丢掉（合并结果只剩一条、运行时只注册一个 provider，构建却不报错），
  必须 `filesMatching("META-INF/services/**") { duplicatesStrategy = DuplicatesStrategy.INCLUDE }`，
  详见 `memshell-party-gui/memshell-party-gui-sdk/README.md`。

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-custom-shelltool-gui:test
```

- `GodzillaSessionGuiExtensionTest`（无需窗口）：SPI 发现与同名去重；插件工具本来就在工具下拉框里、
  扩展面板成功接管；专用面板写入的参数经界面生成链路落到 `GodzillaSessionConfig`；
  `onResultGenerated` 进"生成历史"、结果动作进"我的 Shell 列表"，两者互不干扰。
- `CustomShellGuiFrameTest`（需要显示环境，headless 跳过）：宿主自建外壳装上 SDK 的生成器后，
  自己的工具在工具下拉框里、专用面板已挂上、结果区有自己的动作按钮、状态行接得住生成器上报的消息。
- `FatJarServiceDiscoveryTest`：先打 fat jar（本模块配了 Shadow 的 `mergeServiceFiles()` +
  SPI 文件去重放开，见 build.gradle.kts），
  再断言合并后的 SPI 文件里插件与内置工具共存、`GuiExtension` 条目存活 —— 下游打包时
  最常踩的坑在这里直接可回归。
