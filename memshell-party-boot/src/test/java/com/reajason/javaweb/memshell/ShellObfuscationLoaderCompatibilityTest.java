package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandConfig;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static com.reajason.javaweb.memshell.ShellType.AGENT_FILTER_CHAIN;
import static com.reajason.javaweb.memshell.ShellType.CATALINA_AGENT_CONTEXT_VALVE;
import static com.reajason.javaweb.memshell.ShellType.WAS_AGENT_FILTER_MANAGER;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Agent shell 会被注入器 defineClass 进目标类的 defining loader。对 OSGi 容器
 * （Open Liberty / GlassFish / Payara）而言这是 bundle loader，未 import javax.crypto，
 * class-obf 的 AES 解密例程会让 shell 的 {@code <clinit>} 链接失败，而注入代码的
 * {@code catch (Throwable)} 会静默吞掉。这里守住生成侧契约：这些组合的 shell 产物
 * 不得引用 {@code javax/crypto}，即使用户显式要求开启 AES。
 */
class ShellObfuscationLoaderCompatibilityTest {

    @Test
    void agentShellsDefinedInOsgiBundlesAvoidJavaxCrypto() {
        assertShellHasNoCryptoReference(Server.WebSphere, WAS_AGENT_FILTER_MANAGER);
        assertShellHasNoCryptoReference(Server.GlassFish, AGENT_FILTER_CHAIN);
        assertShellHasNoCryptoReference(Server.GlassFish, CATALINA_AGENT_CONTEXT_VALVE);
    }

    private static void assertShellHasNoCryptoReference(String server, String shellType) {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(server)
                .shellTool(ShellTool.Command)
                .shellType(shellType)
                .targetJreVersion(Opcodes.V1_6)
                .shrink(true)
                .lambdaSuffix(true)
                // 用户显式开启也必须被 server 覆盖，否则 OSGi bundle loader 解析不到 javax.crypto
                .obfuscation(ObfuscationConfig.enabled(Collections.singletonMap("enableAES", true)))
                .build();
        MemShellResult result = new MemShellGenerator().generate(
                shellConfig,
                InjectorConfig.builder().build(),
                CommandConfig.builder().paramName("testParam").build());

        assertNotNull(result.getObfuscationInfo(), "obfuscation should stay enabled");
        assertTrue(result.getObfuscationInfo().isEnabled(), "obfuscation should stay enabled");
        assertFalse(containsJavaxCryptoReference(result.getShellBytes()),
                server + "/" + shellType + " shell must not reference javax.crypto: "
                        + "it is defined by the injector into an OSGi bundle classloader");
    }

    private static boolean containsJavaxCryptoReference(byte[] classBytes) {
        // 类引用以 UTF8 常量池条目保存（如 javax/crypto/Cipher），按 ASCII 扫描即可
        return new String(classBytes, StandardCharsets.ISO_8859_1).contains("javax/crypto/");
    }
}
