# Examples

每个模块演示一类使用方式：**主代码是给下游抄的最小实现，测试把契约锁死**（SPI 发现、
生成产物、真实容器里的注入与使用）。全部模块的测试跑在 unit-test workflow 里。

## 按你的场景选

| 我要…… | 看这个例子 |
|---|---|
| 写一个自己的 shelltool 插件（新工具协议/新形态，进 GUI 下拉框） | [`memshell-party-example-custom-shelltool`](memshell-party-example-custom-shelltool) |
| 给新容器/新场景写注入器（server 插件） | [`memshell-party-example-custom-server`](memshell-party-example-custom-server) |
| 给自己的客户端复用整套桌面 GUI（专用面板/品牌/结果动作） | [`memshell-party-example-custom-shelltool-gui`](memshell-party-example-custom-shelltool-gui) |
| 生成回显马（探测马）摸目标环境 | [`memshell-party-example-probe`](memshell-party-example-probe) |
| 部署真实靶标环境做端到端验证 | 不在 memshell-party-examples，见 `vul/`（靶场应用）与 `integration-test/`（容器级测试） |

## 扩展面

MemShellParty 的主要扩展面在 memshell-party-examples 里各有对应演示：

| 扩展面 | 入口 | 例子 |
|---|---|---|
| shelltool 插件 | `ShellToolProvider` + `@ShellToolMeta` | example-custom-shelltool |
| server 插件（注入器） | `ServerProvider` + `@ServerMeta` | example-custom-server |
| GUI 扩展 | `GuiExtension` | example-custom-shelltool-gui |

## 例子之间的依赖

例子默认互相独立（各自 README 都强调"只引入你要的"），只有一处有意为之的耦合：

- `example-custom-shelltool-gui` 依赖 `example-custom-shelltool` —— 演示"自己的插件以
  jar 形式接入 GUI"（`implementation` 依赖 + SPI 发现）。

## 版本说明

各 README 里的 Maven 坐标版本是发布线示意；在仓库内开发时一律用
`project(":...")` 依赖。发布时以当时的发布版本为准。

## CI 覆盖

`unit-test.yml` 跑全部例子的测试。
