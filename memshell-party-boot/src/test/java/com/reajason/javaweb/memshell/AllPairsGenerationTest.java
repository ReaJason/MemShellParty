package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Generates every advertised (server, shellTool, shellType) combination in one JVM.
 * <p>
 * This is the guard for generation-time bytecode resolution: a shell template's supertypes
 * (catalina, spring, netty, dubbo, jetty, ...) are resolved as class bytes, never loaded, and
 * are compileOnly in the provider modules — so anything missing from this module's runtime
 * classpath only shows up as a generation failure for that one combination.
 *
 * @author ReaJason
 * @since 3.0.0
 */
class AllPairsGenerationTest {

    @Test
    void everyAdvertisedCombinationGenerates() {
        MemShellGenerator memShellGenerator = new MemShellGenerator();
        List<String> combinations = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        for (String serverName : memShellGenerator.getSupportedServers()) {
            AbstractServer server = memShellGenerator.getServer(serverName);
            if (server == null) {
                continue;
            }
            for (String shellTool : new TreeSet<>(server.getSupportedShellTools())) {
                for (String shellType : new TreeSet<>(server.getSupportedShellTypes(shellTool))) {
                    combinations.add(serverName + " / " + shellTool + " / " + shellType);
                    try {
                        ShellConfig shellConfig = ShellConfig.builder()
                                .server(serverName)
                                .shellTool(shellTool)
                                .shellType(shellType)
                                .targetJreVersion(targetJreVersionFor(serverName))
                                .serverVersion(serverVersionFor(serverName, shellType))
                                .build();
                        MemShellResult result = memShellGenerator.generate(shellConfig,
                                InjectorConfig.builder().build(), Collections.emptyMap());
                        assertTrue(result.getShellBytes().length > 0);
                        assertTrue(result.getInjectorBytes().length > 0);
                    } catch (Throwable e) {
                        failures.add(serverName + " / " + shellTool + " / " + shellType + " -> " + e);
                    }
                }
            }
        }
        // 定点断言而非下界：某个 server/shelltool 模块少注册一批 shellType 时，数量必须变化
        // 才能被发现。新增中间件/工具后同步更新这个期望值即可。
        // 669 = 649 + 20（GodzillaSession 增补 request 带 getSession() 的 Agent 场景类型）
        assertEquals(669, combinations.size(), "advertised (server, shellTool, shellType) matrix changed");
        assertEquals(Collections.emptyList(), failures, failures.size() + " combination(s) failed to generate");
    }

    /**
     * Web UI 在选择 SpringWebFlux / XXLJOB / Dubbo 时会把目标 JDK 提升到 Java 8（这些模板使用
     * lambda/invokedynamic，Java 6 类文件写不出来），这里对齐同一个默认值。
     */
    private static int targetJreVersionFor(String serverName) {
        if (Server.SpringWebFlux.equals(serverName)
                || Server.XXLJOB.equals(serverName)
                || Server.Dubbo.equals(serverName)) {
            return Opcodes.V1_8;
        }
        return Opcodes.V1_6;
    }

    /**
     * Jetty Handler 与 TongWeb Valve 的父类/包名前缀随中间件版本变化，必须显式指定版本才能生成。
     * 单个版本的逐版本覆盖见 CommandJettyHandlerTest。
     */
    private static String serverVersionFor(String serverName, String shellType) {
        if (Server.Jetty.equals(serverName)
                && (ShellType.HANDLER.equals(shellType) || ShellType.JAKARTA_HANDLER.equals(shellType))) {
            return "7+";
        }
        if (Server.TongWeb.equals(serverName)
                && (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType))) {
            return "8";
        }
        return null;
    }
}
