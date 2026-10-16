package com.reajason.javaweb.examples.customshellgui;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarFile;

import static org.junit.jupiter.api.Assertions.*;

/**
 * fat jar 打包验证：下游用 Shadow 打 fat jar 时必须 {@code mergeServiceFiles()}，
 * 否则 {@code META-INF/services} 里只剩最后一个 jar 的条目 —— ShellToolProvider
 * 只看到内置工具、GuiExtension 整个丢失。本测试直接检查打出来的 fat jar：
 * 合并后的 SPI 文件里，插件和扩展与内置提供者共存。
 *
 * <p>类加载层的 SPI 发现（ServiceLoader）由 GodzillaSessionGuiExtensionTest 在
 * reactor 类路径上验证；这里验证的是"打包"这一步，两者合起来才是完整链路。
 *
 * @author ReaJason
 */
class FatJarServiceDiscoveryTest {

    private static final String SHELL_TOOL_SPI = "META-INF/services/com.reajason.javaweb.memshell.spi.ShellToolProvider";
    private static final String GUI_EXTENSION_SPI = "META-INF/services/com.reajason.javaweb.desktop.memshell.extension.GuiExtension";

    @Test
    void spiFilesSurviveShadowMerging() throws Exception {
        File jarFile = findShadowJar();
        try (JarFile jar = new JarFile(jarFile)) {
            // 插件条目与内置条目在同一份文件里：mergeServiceFiles() 确实合并了
            assertServiceContains(jar, SHELL_TOOL_SPI, "GodzillaSessionShellToolProvider",
                    "插件工具没进 fat jar 的 SPI 文件");
            assertServiceContains(jar, SHELL_TOOL_SPI, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaShellToolProvider",
                    "合并把内置工具条目丢了");
            // GuiExtension 条目也活着：扩展跟插件一样会被吞
            assertServiceContains(jar, GUI_EXTENSION_SPI, "GodzillaSessionGuiExtension",
                    "GUI 扩展没进 fat jar 的 SPI 文件");
        }
    }

    private static File findShadowJar() {
        File libsDir = new File("build/libs");
        assertTrue(libsDir.isDirectory(), "build/libs 不存在：先跑 shadowJar");
        File[] jars = libsDir.listFiles((dir, name) -> name.endsWith("-all.jar"));
        assertNotNull(jars, "build/libs 不可读");
        assertTrue(jars.length > 0, "没有找到 *-all.jar：shadowJar 没有产出？");
        return jars[0];
    }

    private static void assertServiceContains(JarFile jar, String entryName, String expectedLine, String message) throws Exception {
        java.util.jar.JarEntry entry = jar.getJarEntry(entryName);
        assertNotNull(entry, message + "：" + entryName + " 不存在于 fat jar");
        try (InputStream in = jar.getInputStream(entry);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String content = reader.lines()
                    .filter(line -> !line.trim().isEmpty() && !line.trim().startsWith("#"))
                    .reduce((a, b) -> a + "\n" + b)
                    .orElse("");
            assertTrue(content.contains(expectedLine),
                    message + "：" + entryName + " 里没有 " + expectedLine + "，实际内容：\n" + content);
        }
    }
}
