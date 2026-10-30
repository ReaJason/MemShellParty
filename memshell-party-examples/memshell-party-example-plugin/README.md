# 外置 SPI 插件示例

本模块构建一个不带 GUI 代码的插件 jar，同时提供 `ServerProvider`、`ShellToolProvider` 和 `Packer`。示例使用独立 shellType，只演示生成链路，不针对真实中间件执行注入。

## 构建与安装

在仓库根目录执行：

```bash
./gradlew :memshell-party-examples:memshell-party-example-plugin:shadowJar
```

将 `build/libs/memshell-party-example-plugin-*.jar` 复制到启动 jar 同级的 `plugins/`：

```text
memshell-party-boot-x.y.z.jar
memshell-party-gui-x.y.z.jar
plugins/
  memshell-party-example-plugin-x.y.z.jar
```

重启后，REST、MCP 和桌面端会出现 `ExamplePluginServer`、`ExamplePluginTool`、`ExampleBase64URL`。修改或删除插件同样需要重启。

可用系统属性或环境变量覆盖目录；系统属性优先，相对路径以启动 jar 所在目录为基准：

```bash
java -Dmemshell.plugins.dir=/path/to/plugins -jar memshell-party-boot-x.y.z.jar
MEMSHELL_PLUGINS_DIR=/path/to/plugins java -jar memshell-party-gui-x.y.z.jar
```

## 编写插件

- 宿主提供的 `memshell-party-api`、`memshell-party-core` 使用 `compileOnly`，不要打入插件。
- 插件自己的第三方运行期依赖使用 `implementation`，由 Shadow 打入 fat jar。
- 使用 `@MetaInfServices` 或手写 `META-INF/services`；fat jar 必须合并服务描述符。
- 注册名不能与内置能力或其他插件重复。内置项优先，插件按 jar 文件名排序，重名保留先加载项。
- 单个 provider 加载失败会记录警告并跳过，不阻止宿主启动。
- 首版仅扫描目录第一层，不支持热加载、卸载、插件间依赖隔离或插件提供的 `GuiExtension`。

插件与宿主具有相同代码执行权限，只安装可信 jar。
