package com.reajason.javaweb.examples.customgui.gui;

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
 * 只看到内置工具、自定义 server/packer/GuiExtension 整个丢失。本测试直接检查打出来的
 * fat jar：四类 SPI 文件的合并结果里，自定义提供者与内置提供者共存。
 *
 * <p>类加载层的 SPI 发现（ServiceLoader）由其余测试在 reactor 类路径上验证；
 * 这里验证的是"打包"这一步，两者合起来才是完整链路。
 *
 * @author ReaJason
 */
class FatJarServiceDiscoveryTest {

    private static final String SERVER_SPI = "META-INF/services/com.reajason.javaweb.memshell.spi.ServerProvider";
    private static final String SHELL_TOOL_SPI = "META-INF/services/com.reajason.javaweb.memshell.spi.ShellToolProvider";
    private static final String PACKER_SPI = "META-INF/services/com.reajason.javaweb.packer.Packer";
    private static final String GUI_EXTENSION_SPI = "META-INF/services/com.reajason.javaweb.desktop.memshell.extension.GuiExtension";

    @Test
    void spiFilesSurviveShadowMerging() throws Exception {
        File jarFile = findShadowJar();
        try (JarFile jar = new JarFile(jarFile)) {
            // 自定义 server 与内置 Tomcat 在同一份文件里：mergeServiceFiles() 确实合并了
            assertServiceContains(jar, SERVER_SPI,
                    "com.reajason.javaweb.examples.customgui.server.DemoServerProvider",
                    "自定义 server 没进 fat jar 的 SPI 文件");
            assertServiceContains(jar, SERVER_SPI,
                    "com.reajason.javaweb.memshell.server.tomcat.TomcatServerProvider",
                    "合并把内置 server 条目丢了");
            // 自定义 shelltool 与内置 Godzilla 共存
            assertServiceContains(jar, SHELL_TOOL_SPI,
                    "com.reajason.javaweb.examples.customgui.shelltool.GodzillaSessionShellToolProvider",
                    "自定义工具没进 fat jar 的 SPI 文件");
            assertServiceContains(jar, SHELL_TOOL_SPI,
                    "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaShellToolProvider",
                    "合并把内置工具条目丢了");
            // 自定义 packer 与内置 Base64 共存
            assertServiceContains(jar, PACKER_SPI,
                    "com.reajason.javaweb.examples.customgui.packer.GzipBase64URLPacker",
                    "自定义 packer 没进 fat jar 的 SPI 文件");
            assertServiceContains(jar, PACKER_SPI,
                    "com.reajason.javaweb.packer.base64.DefaultBase64Packer",
                    "合并把内置 packer 条目丢了");
            // GuiExtension 条目也活着：扩展跟插件一样会被吞
            assertServiceContains(jar, GUI_EXTENSION_SPI,
                    "com.reajason.javaweb.examples.customgui.gui.GodzillaSessionGuiExtension",
                    "GUI 扩展没进 fat jar 的 SPI 文件");
        }
    }

    private static File findShadowJar() {
        File libsDir = new File("build/libs");
        assertTrue(libsDir.isDirectory(), "build/libs 不存在：先跑 shadowJar");
        // 发行物是无分类器的 memshell-party-custom-gui-<version>.jar，裸 jar 带 -plain
        File[] jars = libsDir.listFiles((dir, name) ->
                name.startsWith("memshell-party-custom-gui-") && name.endsWith(".jar") && !name.endsWith("-plain.jar"));
        assertNotNull(jars, "build/libs 不可读");
        assertTrue(jars.length > 0, "没有找到 memshell-party-custom-gui-*.jar：shadowJar 没有产出？");
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
