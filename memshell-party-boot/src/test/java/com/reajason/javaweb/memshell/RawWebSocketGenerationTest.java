package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RawWebSocket 的 shell 与 helper 只靠类名约定协作：shell 用自身类字面量拼出
 * {@code <shellClassName>$RawWsHelper} 找 helper，注入器必须先 defineClass 同名类。
 * 这里验证生成期把 helper 以派生类名嵌进注入器，且 shell 的类字面量确实被重命名。
 *
 * @author ReaJason
 * @since 2025/10/24
 */
class RawWebSocketGenerationTest {

    private static final String HELPER_SUFFIX = "$RawWsHelper";

    @Test
    void plainShellTypesCarryNoHelper() throws Exception {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Command)
                .shellType(ShellType.FILTER)
                .targetJreVersion(Opcodes.V1_6)
                .build();
        MemShellResult result = new MemShellGenerator().generate(shellConfig,
                InjectorConfig.builder().build(), Collections.emptyMap());
        assertNull(result.getHelperClassName());
        assertNull(result.getHelperBytes());
        assertNull(result.getHelperBytesBase64Str());
        assertEquals(0, result.getHelperSize());
    }

    @Test
    void rawWebSocketRequiresSpecificUrlPattern() {
        MemShellGenerator generator = new MemShellGenerator();
        for (String shellType : Arrays.asList(ShellType.RAW_WEBSOCKET, ShellType.JAKARTA_RAW_WEBSOCKET)) {
            ShellConfig shellConfig = ShellConfig.builder()
                    .server(Server.Tomcat)
                    .shellTool(ShellTool.Proxy)
                    .shellType(shellType)
                    .targetJreVersion(Opcodes.V1_6)
                    .build();
            for (String urlPattern : Arrays.asList(null, "", " ", "/", "/*", "ws")) {
                GenerationException exception = assertThrows(GenerationException.class,
                        () -> generator.generate(shellConfig, InjectorConfig.builder()
                                .urlPattern(urlPattern)
                                .build(), Collections.emptyMap()));
                assertEquals(shellType + " requires a specific urlPattern, e.g. /ws", exception.getMessage());
            }
            GenerationException exception = assertThrows(GenerationException.class,
                    () -> generator.generate(shellConfig, null, Collections.emptyMap()));
            assertEquals(shellType + " requires a specific urlPattern, e.g. /ws", exception.getMessage());
        }
    }

    @Test
    void helperIsEmbeddedUnderDerivedShellClassName() throws Exception {
        for (String server : Arrays.asList(Server.Tomcat, Server.BES, Server.TongWeb,
                Server.GlassFish, Server.Undertow, Server.Jetty, Server.WebLogic)) {
            verifyHelperEmbedded(server, Arrays.asList(ShellType.RAW_WEBSOCKET, ShellType.JAKARTA_RAW_WEBSOCKET));
        }
        // Resin 3/4 只有 javax 命名空间
        verifyHelperEmbedded(Server.Resin, Collections.singletonList(ShellType.RAW_WEBSOCKET));
        // 传统 WebSphere 7/8.5/9、Apusic 9、InforSuite 9/10 只有 javax Servlet API
        verifyHelperEmbedded(Server.WebSphere, Collections.singletonList(ShellType.RAW_WEBSOCKET));
        verifyHelperEmbedded(Server.Apusic, Collections.singletonList(ShellType.RAW_WEBSOCKET));
        verifyHelperEmbedded(Server.InforSuite, Collections.singletonList(ShellType.RAW_WEBSOCKET));
    }

    @Test
    void defaultAllScopeEmbedsTheObfuscatedHelperCopy() throws Exception {
        Map<String, Object> options = new HashMap<>();
        options.put("enableAES", false);
        options.put("enableAdvanceString", false);
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Command)
                .shellType(ShellType.RAW_WEBSOCKET)
                .targetJreVersion(Opcodes.V1_6)
                .obfuscation(ObfuscationConfig.enabled(options))
                .build();
        MemShellResult result = new MemShellGenerator().generate(shellConfig,
                InjectorConfig.builder().urlPattern("/raw-ws").build(), Collections.emptyMap());

        assertArrayEquals(result.getHelperBytes(), extractHelperBytes(result.getInjectorBytes()));
    }

    @Test
    void defaultAllScopeSupportsEveryRawWebSocketHelper() {
        List<String> servers = Arrays.asList(Server.Tomcat, Server.GlassFish, Server.Undertow,
                Server.Jetty, Server.WebLogic, Server.Resin, Server.WebSphere, Server.Apusic);
        for (String server : servers) {
            ShellConfig shellConfig = ShellConfig.builder()
                    .server(server)
                    .shellTool(ShellTool.Command)
                    .shellType(ShellType.RAW_WEBSOCKET)
                    .targetJreVersion(Opcodes.V1_6)
                    .obfuscation(ObfuscationConfig.enabled())
                    .build();
            MemShellResult result = new MemShellGenerator().generate(shellConfig,
                    InjectorConfig.builder().urlPattern("/raw-ws").build(), Collections.emptyMap());

            assertNotNull(result.getHelperBytes(), server);
            assertEquals(result.getShellClassName() + HELPER_SUFFIX, result.getHelperClassName(), server);
            assertEquals(Opcodes.V1_6, new ClassReader(result.getHelperBytes()).readUnsignedShort(6), server);
            assertTrue(hasPublicMethod(result.getHelperBytes(), "equals", "(Ljava/lang/Object;)Z"), server);
            assertTrue(hasPublicMethod(result.getHelperBytes(), "close", "()V"), server);
        }
    }

    private void verifyHelperEmbedded(String server, List<String> shellTypes) throws Exception {
        for (String shellType : shellTypes) {
            for (String shellTool : Arrays.asList(ShellTool.Command, ShellTool.Godzilla, ShellTool.Proxy)) {
                ShellConfig shellConfig = ShellConfig.builder()
                        .server(server)
                        .shellTool(shellTool)
                        .shellType(shellType)
                        .targetJreVersion(Opcodes.V1_6)
                        .build();
                MemShellResult result = new MemShellGenerator().generate(shellConfig,
                        InjectorConfig.builder().urlPattern("/raw-ws").build(), Collections.emptyMap());

                String expectedHelperName = result.getShellClassName().replace('.', '/') + HELPER_SUFFIX;
                byte[] helperBytes = extractHelperBytes(result.getInjectorBytes());
                assertNotNull(helperBytes, server + "/" + shellType + "/" + shellTool + " injector carries no helper");
                assertEquals(expectedHelperName, new ClassReader(helperBytes).getClassName(),
                        server + "/" + shellType + "/" + shellTool + " helper name must match the name the shell derives");
                // 结果对象直出 helper，供 GUI/web 的辅助类 Tab 展示
                assertEquals(expectedHelperName.replace('/', '.'), result.getHelperClassName(),
                        server + "/" + shellType + "/" + shellTool + " result helper class name");
                assertEquals(Base64.getEncoder().encodeToString(helperBytes), result.getHelperBytesBase64Str(),
                        server + "/" + shellType + "/" + shellTool + " result helper bytes must match the embedded copy");
                assertEquals(helperBytes.length, result.getHelperSize(),
                        server + "/" + shellType + "/" + shellTool + " result helper size");
                assertEquals(Opcodes.V1_6, new ClassReader(helperBytes).readUnsignedShort(6),
                        server + "/" + shellType + "/" + shellTool + " helper must match the configured target JDK");
                assertTrue(hasPublicMethod(helperBytes, "close", "()V"),
                        server + "/" + shellType + "/" + shellTool
                                + " helper must expose public close() so shells can end failed sessions");

                String shellDump = new String(result.getShellBytes(), StandardCharsets.ISO_8859_1);
                assertTrue(shellDump.contains(HELPER_SUFFIX),
                        server + "/" + shellType + "/" + shellTool + " shell does not derive the helper name");
                assertTrue(shellDump.contains(result.getShellClassName().replace('.', '/')),
                        server + "/" + shellType + "/" + shellTool + " shell class literal was not renamed to the generated class name");
                assertTrue(classConstants(result.getShellBytes()).contains(result.getShellClassName()),
                        server + "/" + shellType + "/" + shellTool + " shell self class literal was not remapped, got "
                                + classConstants(result.getShellBytes()));
                if (ShellType.JAKARTA_RAW_WEBSOCKET.equals(shellType)) {
                    assertTrue(shellDump.contains("jakarta/servlet/Filter"),
                            server + "/" + shellType + "/" + shellTool + " shell was not relocated to Jakarta");
                } else {
                    assertTrue(shellDump.contains("javax/servlet/Filter"),
                            server + "/" + shellType + "/" + shellTool + " shell must stay on javax");
                }
            }
        }
    }

    private static boolean hasPublicMethod(byte[] classBytes, final String name, final String descriptor) {
        final boolean[] found = new boolean[1];
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String methodName, String methodDescriptor,
                                             String signature, String[] exceptions) {
                if (name.equals(methodName) && descriptor.equals(methodDescriptor)
                        && (access & Opcodes.ACC_PUBLIC) != 0) {
                    found[0] = true;
                }
                return null;
            }
        }, 0);
        return found[0];
    }

    private static Set<String> classConstants(byte[] classBytes) {
        final Set<String> names = new HashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof Type && ((Type) value).getSort() == Type.OBJECT) {
                            names.add(((Type) value).getClassName());
                        }
                    }
                };
            }
        }, 0);
        return names;
    }

    /**
     * 遍历注入器里所有字符串常量，找出解码后是 helper 类文件的那个。
     */
    private static byte[] extractHelperBytes(byte[] injectorBytes) throws IOException {
        final byte[][] found = new byte[1][];
        new ClassReader(injectorBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (!(value instanceof String) || found[0] != null) {
                            return;
                        }
                        try {
                            byte[] decoded = gzipDecompress(Base64.getDecoder().decode((String) value));
                            String className = new ClassReader(decoded).getClassName();
                            if (className.endsWith(HELPER_SUFFIX)) {
                                found[0] = decoded;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                };
            }
        }, 0);
        return found[0];
    }

    private static byte[] gzipDecompress(byte[] compressed) throws IOException {
        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = input.read(buffer)) > 0) {
                output.write(buffer, 0, n);
            }
            return output.toByteArray();
        }
    }
}
