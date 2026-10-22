# Examples

每个模块演示一类使用方式：**主代码是给下游抄的最小实现，测试把契约锁死**（SPI 发现、
生成产物、真实容器里的注入与使用）。全部模块的测试跑在 unit-test workflow 里。

## 按你的场景选

| 我要…… | 看这个例子 |
|---|---|
| 写一个自己的 shelltool 插件（新工具协议/新形态，进 GUI 下拉框） | [`memshell-party-example-custom-gui`](memshell-party-example-custom-gui) |
| 给新容器/新场景写注入器（server 插件） | [`memshell-party-example-custom-gui`](memshell-party-example-custom-gui) |
| 写一个自己的 packer（新的投递编码/传输形态） | [`memshell-party-example-custom-gui`](memshell-party-example-custom-gui) |
| 给自己的客户端复用整套桌面 GUI（专用面板/品牌/结果动作） | [`memshell-party-example-custom-gui`](memshell-party-example-custom-gui) |
| 生成回显马（探测马）摸目标环境 | [`memshell-party-example-probe`](memshell-party-example-probe) |
| 部署真实靶标环境做端到端验证 | 不在 memshell-party-examples，见 `vul/`（靶场应用）与 `integration-test/`（容器级测试） |

## 扩展面

MemShellParty 的主要扩展面都在 `memshell-party-example-custom-gui` 里演示，四块拼图装进同一个
可运行桌面程序：

| 扩展面 | 入口 | 例子里的实现 |
|---|---|---|
| server 插件（注入器） | `ServerProvider` + `@ServerMeta` | `custom-gui/server` |
| shelltool 插件 | `ShellToolProvider` + `@ShellToolMeta` | `custom-gui/shelltool` |
| packer 插件 | `Packer` + `@PackerMeta` | `custom-gui/packer` |
| GUI 扩展 | `GuiExtension` | `custom-gui/gui` |

## 例子之间的依赖

例子默认互相独立（各自 README 都强调"只引入你要的"），`custom-gui` 在自己的模块内演示
「自定义 provider 与内置 provider 共存」，不再跨例子依赖。

## 版本说明

各 README 里的 Maven 坐标版本是发布线示意；在仓库内开发时一律用
`project(":...")` 依赖。发布时以当时的发布版本为准。

## CI 覆盖

`unit-test.yml` 跑全部例子的测试；`release.yaml` 把 `custom-gui` 的 fat jar 作为发行物上传。
