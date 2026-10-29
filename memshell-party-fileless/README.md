# Fileless Agent runtime

`FilelessAgentPacker` 实现 `Packer.pack(MemShellResult)`，仅接受 Agent shell 类型。返回值是 Base64 文本；解码后只有一个 public、带 public 无参构造函数的 Java 6 类，不是 JAR，也不实现 `JarPacker`。

目标可通过 Tomcat 靶场 `/b64` 的 `defineClass(...).newInstance()` 直接投递。构造函数会：

1. 解码内嵌的 gzip 数据，动态定义 `JarLoader`、native provider 及其辅助类；每次产物使用独立包名，目标无需预装 `memshell-party-fileless`。
2. 获取同时具备 redefine/retransform 能力的真实 `Instrumentation`。
3. 从内存加载带 `Fileless-Agent-Contract: 1` 的 Agent JAR，依次查找 `agentmain(String, Instrumentation)`、单参数 `agentmain` 及对应 `premain`。
4. 恢复线程上下文 ClassLoader；`toString()` 不重复注入。

生成侧使用当前项目的 `AgentJarPacker` 和 `JarLoader`，不依赖 noone，不在目标写 Agent JAR，也不调用 jattach。

已有真实 `Instrumentation` 时，也可直接调用：

```java
ClassLoader agentLoader = FilelessAgentBootstrap.install(
        agentJar, agentArgs, instrumentation, parentLoader);
```

## 当前支持边界

| 路径 | 状态 |
| --- | --- |
| 目标侧类文件 | runtime、Bootstrap 与验证 fixture 均为 class-file 50 |
| 外部 `Instrumentation` + 内存加载 + retransform | JRE 6、8、17、21、25 验证路径 |
| 无外部 Agent 获取 `Instrumentation` | Windows/x64 HotSpot，以及 Linux/amd64、Linux/arm64 上的 HotSpot、OpenJ9；均按当前映射动态解析，实际运行时见 `VERIFICATION.md` |
| 无法解析的 JRE | 必需符号、映射或 JPLIS 布局缺失或有歧义时，在修改 native 状态前拒绝；不能由 class-file 50 推定支持 |
| Windows 其他架构及 OpenJ9 | 尚未实现已验证的 native provider |
| BiSheng 及其他 OpenJDK 衍生版 | 不按 OpenJDK 血统推定兼容，以当前运行构建的实际解析结果为准 |

每次获取都重新解析当前进程。Linux 读取 `/proc/self/maps` 和已映射 ELF64，通过 `PT_LOAD` 校验 load bias、符号地址及原始字节，不保存版本白名单、native 哈希或预置偏移。HotSpot 将 `getInitiatedClasses0` JNI 入口临时跳转到同一 `libinstrument.so` 内 `setNativeMethodPrefixes` 的函数容量；宿主与入口在首次写入前分别校验，恢复顺序相反。amd64 内部符号被剥离时，从 Agent/JNI 调用图与 `.eh_frame` FDE 范围恢复函数，并交叉验证调用语义和 JPLIS 数据流。OpenJ9 使用唯一 `libjclse*.so` JNI 入口，并按目录共址排除 JVM redirector。JPLIS 字段偏移由有界 x86-64 或 AArch64 CFG 数据流推导，包含 Temurin 21 和 Semeru 25 的 warning 字段，不回退到固定 `0x38` 或 `0x78`。

Windows/x64 从 PEB 和已映射 PE32+ 镜像解析 JVM、`instrument.dll`、导出表及 `.pdata` 函数边界，按 Win64 ABI 恢复 JPLIS 调用图与字段布局。获取 stub 通过 JDK 自身 attach 队列执行，使用 `WriteProcessMemory` 和 `FlushInstructionCache` 完成临时修改，再由真正的 JNI 调用返回 `Instrumentation`；JDK 6/8 与 JDK 9+ 的 attach JNI 类名分别处理。宿主与触发入口的原始字节在写入前校验，并在 `finally` 中逆序恢复、逐字节读回验证。所有平台的获取过程均由进程内锁串行化。

动态 native fixture 的通过项均包含无 `-javaagent` 的两次获取、完整 native 字节恢复，以及真实 `Target.value()` 从 7 到 8 的 retransform。Linux 最终双 patch 回归为 7/7 通过；Windows/x64 的 JDK 6、8、11、17 矩阵为 7/7 通过，并对同一矩阵验证了真实 `FilelessAgentPacker` 产物的完整内存 Agent 安装与 retransform。详细运行时和独立恢复校验位置见 `VERIFICATION.md`。
