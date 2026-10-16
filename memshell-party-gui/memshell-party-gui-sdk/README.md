# memshell-party-gui-sdk

MemShellParty 桌面端（Swing）的**可扩展 SDK**：提供三个界面 ——
内存马生成器 `MemShellGeneratorFrame`、探测马生成器 `ProbeGeneratorFrame`、
CFR 反编译工具 `DecompileFrame` —— 加上扩展点。
页签怎么排、状态栏长什么样、「关于」放哪儿、外壳是什么牌子，都是宿主自己的事
（官方完整发行版的外壳见 `memshell-party-gui-app`）。
下游把它当普通依赖引入，就有能生成内存马/探测马、反编译类字节的界面，按自己的布局装进产品里 ——
不用自己从零写一套 Swing 生成器（[dandelion-client](https://github.com/ReaJason/dandelion)
那种自带 shelltool 的客户端就是目标场景）。

## 两个 GUI 模块的分工

| | `memshell-party-gui/memshell-party-gui-sdk`（本模块） | `memshell-party-gui/memshell-party-gui-app` |
|---|---|---|
| 内容 | 三个界面 frame（两个生成器 + 反编译工具）、扩展点、工具参数动态表单 | SDK + 官方外壳（页签布局 / 状态栏 / 关于弹窗 / 暗色切换）+ `server-all` + `shelltool-all` + 入口类 |
| 形态 | 普通依赖 jar（发布到 Maven Central） | 全量 fat jar（GitHub Releases 里的 `memshell-party-gui-x.y.z.jar`） |
| 内置 server | **不带**，下游按需引入 | 全部 19 个 |
| 内置 shelltool | 全部 8 个（表单按 config 上的 `@ConfigField` 生成） | 全部 8 个 |
| 用途 | 下游写自己的客户端 / 集成进已有产品 | 双击即用、命令行 `java -jar` |

## 引入

```kotlin
dependencies {
    // 两个生成器界面与扩展点
    implementation("io.github.reajason:memshell-party-gui-sdk:<version>")
    // server 不随 SDK 走，用哪个引哪个（要全部就换成 memshell-party-server-all）
    implementation("io.github.reajason:memshell-party-server-tomcat:<version>")
}
```

仓库内开发时直接 `implementation(project(":memshell-party-gui:memshell-party-gui-sdk"))`。SDK 通过 `api` 暴露了
`memshell-party-core`（扩展点里的 `ShellToolConfig`/`MemShellResult` 等类型要在下游编译期可见），
其余依赖（packer、内置 shelltool、FlatLaf/MigLayout/CFR、生成期签名包）都是 runtime scope。

> 一个 server 都不引时界面能打开，但工具下拉框是空的（列表 = server 的注入器映射 × 工具声明求交集）。
> 需要其它内置工具时同理加 `memshell-party-shelltool-*`。

## 拿到界面

```java
// 独立窗口：自带窗口属性与 Ctrl/⌘ + Enter 快捷键，一行就能跑
MemShellGui.createMemShellFrame();          // 类路径上所有 GuiExtension（SPI）自动挂上
MemShellGui.createProbeFrame().setVisible(true);
MemShellGui.createDecompileFrame().setVisible(true);

// 嵌进自己的布局：外壳（页签 / 状态栏 / 关于）全归宿主
MemShellGui.setupLookAndFeel();             // 用 MemShellParty 的观感；自己已有主题就别调
MemShellGeneratorFrame memShell = new MemShellGeneratorFrame(MemShellGui.resolveExtensions(), false);
myTabs.addTab("内存马", memShell.getRootPanel());
memShell.setStatusReporter(myStatusBar::setStatus);    // 自己的状态出口
memShell.installGenerateShortcut(getRootPane());       // Ctrl/⌘ + Enter 与默认按钮挂到自己的窗口

DecompileFrame decompile = new DecompileFrame(false);  // 反编译工具同样能嵌
myTabs.addTab("反编译", decompile.getRootPanel());
decompile.setStatusReporter(myStatusBar::setStatus);
```

内嵌时的三个接线点（三个界面完全对称，反编译的把 `Generate` 换成 `Decompile`）：

| 成员 | 作用 | 不接时 |
|---|---|---|
| `getRootPanel()` | 界面本体（配置区 + 结果区），放进宿主的页签/面板 | —— |
| `setStatusReporter(StatusReporter)` | 生成中/成功·耗时/失败/校验失败（反编译：反编译中/成功/失败）的消息出口 | 静默丢弃（校验错误仍行内标红、生成失败仍弹错误框） |
| `installGenerateShortcut(JRootPane)` | Ctrl/⌘ + Enter + 默认按钮（裸 Enter）；同一窗口换页时让当前页再调一次即可转移 | 没有快捷键 |
| `uninstallGenerateShortcut(JRootPane)` | 摘掉上面那两样；宿主在生成页之外还有别的页签时，离开生成页就调它 | 别的页里 Enter / Ctrl(⌘) + Enter 会误触发一次生成 |

`standalone = false` 构造的 frame 不会自己设置窗口属性（也不会显示）；`getRootPanel()` 返回的组件
只能有一个父容器，内嵌了就别再 `setVisible(true)` 那个 frame。

两个 frame 都继承 `MemShellFrame` —— 窗口骨架只写一遍：内容懒构建、独立/内嵌两种用法、
状态出口、生成按钮与快捷键、生成中的忙碌态与「成功·耗时 / 失败」回报、校验失败的行内标红 + 焦点跳转。
宿主**自己**也有生成页要挂时直接继承它：构造末尾调 `installContent(standalone)`，实现
`buildRootPanel()` / `triggerGenerate()` / `applyValidationErrors()` / `validationFocusTarget()`，
其余骨架不再重写（生成流程用 `runGenerate(task, onSuccess)` 收尾）。
反编译工具不生成东西、也没有校验，所以没继承 `MemShellFrame`，只复用骨架里跟生成无关的部分
（`SwingUiUtil.sizeToScreen`、`FrameShortcutUtil`）。

## 轻量反馈（`SwingUiUtil.showToast`）

宿主界面要提示「这一下没成」（前置不满足、输入不合法、文件读不了）时，用浮层，不用弹窗也不用行内错误 label：

```java
SwingUiUtil.showToast(panel, "URL 不能为空：先填目标地址再探测");
```

浮层挂在 `owner` 所在窗口的 layered pane 底部：圆角药丸，淡入 → 停留 2.4 秒 → 淡出后自动移除。
不改任何组件尺寸（行内错误 label 一显形就会改行高、把整块表单推来推去）、不抢焦点、
不吃鼠标事件（`contains` 恒 false，浮层下方该点哪儿还点哪儿），同一窗口后一条顶掉前一条，
长文案按字符宽度折行，窗口改尺寸时跟着重新定位。后台线程直接调也安全（自动收口到 EDT）。

浮层看完就没了，需要回看的信息要同时写进宿主自己的日志/状态出口。SDK 自带的两个生成器界面
仍按原样走（校验行内标红 + 焦点跳转，`setStatusReporter` 不接时错误弹框），改不改由宿主决定。

## 动作按钮不抢焦点（`SwingUiUtil.actionButton`）

会进忙碌态（跑起来先 `setEnabled(false)`、跑完放开）的按钮，用 `actionButton` 建；宿主自己造的这类按钮
补一句 `SwingUiUtil.markActionButton(button)`：

```java
private final JButton probeButton = SwingUiUtil.actionButton("探测");
```

它们统一 `setFocusable(false)`。原因是实测到的连锁反应：Swing 在「当前焦点持有者被禁用」时把焦点交给
焦点遍历序里的**下一个组件**，生成器里「生成内存马」后面正是配置输入框，于是点一次生成焦点就落进输入框，
FlatLaf 默认 `TextComponent.selectAllOnFocusPolicy=once` 再把它整段选中——看着像被误选，而且下一次输入
会直接顶掉原文。按钮不参与遍历后，点击动作不会把焦点从用户刚编辑的字段里带走（禁用时也没有焦点可移交），
只是它不再进 Tab 序。

鼠标点击、Ctrl/⌘ + Enter、宿主 rootPane 的默认按钮（裸 Enter）、快捷键这几条路径都不受影响——
默认按钮走的是 WHEN_IN_FOCUSED_WINDOW 绑定，与焦点遍历无关（`ActionButtonFocusTest` 锁定）。
反过来说，需要被 Tab 到、或要显示焦点的按钮（保存、切换视图、弹窗底部按钮）不要用这个工厂。

## 反编译工具（`DecompileFrame`）

Base64 / GzipBase64 文本或 `.class` 文件进，CFR 反编译出的 Java 源码出：

- 输入形态自动识别（gzip 魔数 → 先解压；class 魔数 → ASM 读类名），不用用户选，识别结果（类名 + 大小）显示在输入行右侧
- 粘贴或选文件后自动反编译一次（去抖 400ms），「反编译」按钮（Ctrl/⌘ + Enter）可随时重跑；反编译在后台线程跑，期间输入变了就丢弃在途结果
- 源码可复制、保存为 `.java`；卡在 `ClassBytesDecoder`（纯解码，不碰界面），反编译走结果区同款 `CfrDecompileService`

自己的 shelltool 只要按插件方式注册（`@MetaInfServices(ShellToolProvider.class)`，见
`memshell-party-examples/memshell-party-example-custom-shelltool`），就会自动出现在工具下拉框里，参数面板按 config 类上的
`@ConfigField` 注解自动生成（`DynamicToolPanel`）—— 内置工具走的是同一份实现。要专用面板、结果动作时再加
`GuiExtension`，见下表。

## 扩展点（`com.reajason.javaweb.desktop.memshell.extension`）

这里的方法都被内存马生成器界面消费；页面外壳（页签、状态栏、关于弹窗）是宿主自己的实现，
SDK 不提供也不接管。

| 方法 | 作用 | 不实现时 |
|---|---|---|
| `name()` | 扩展名（按名字去重） | 必填 |
| `applicationTitle(default)` | 生成器窗口标题 | `MemShellParty v<版本>` |
| `toolPanels()` | 工具名 → 面板工厂（可覆盖内置面板） | 注解生成的动态参数面板 |
| `resultActions()` | 结果区动作按钮（无结果时自动置灰） | 没有按钮 |
| `onResultGenerated(result)` | 生成成功回调（EDT 上执行） | 不回调 |

面板继承 `AbstractToolPanel` 即自带「挂载类型 + 请求路径」公共字段；参数读写仍走
`controller.setToolParam(name, value)`（key 即 config 字段名），与动态面板同一条链路
（`toolParams → 工具 config 的 @ConfigField 字段 → 生成期写进内存马字段`）。

完整可运行示例：`memshell-party-examples/memshell-party-example-custom-shelltool-gui`
（含一个自建外壳 `CustomShellFrame`，演示上面三件套怎么接线）。

## 构建与测试

```bash
./gradlew :memshell-party-gui:memshell-party-gui-sdk:test     # 界面框架测试（含 SPI 发现、插件工具兜底面板、状态出口）
./gradlew :memshell-party-gui:memshell-party-gui-app:test     # 官方外壳测试（页签/状态栏/装配）
./gradlew :memshell-party-gui:memshell-party-gui-app:shadowJar   # 打全量 fat jar（GitHub Releases 的发行物）
```

## 下游自己打 fat jar 时注意（Shadow 9 的坑）

`ServiceLoader` 靠 `META-INF/services` 发现 `ShellToolProvider`/`GuiExtension`，多个 jar 的同名文件必须合并。
Shadow 9 的 `ShadowJar` 默认 `duplicatesStrategy = EXCLUDE`，**重复文件在进 transformer 之前就被丢掉**，
`mergeServiceFiles()` 每个文件只能看到一份，合并结果只剩一条 —— 构建一路成功，坏掉的只有发行物
（运行时只注册一个 provider）。必须给 SPI 文件单独放开：

```kotlin
tasks.shadowJar {
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    mergeServiceFiles()
}
```

别把 `duplicatesStrategy` 全局改成 `INCLUDE`：`.class` 分支不经过 transformer，重复的类会原样打进包里。
`memshell-party-gui-app` 的 `shadowJar` 里带了打包后自检（开包数 SPI 条目，见 `build.gradle.kts`），
合并失效时直接构建失败。
