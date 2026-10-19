package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.obfuscation.fixtures.InnerHelper;
import com.reajason.javaweb.memshell.obfuscation.fixtures.OuterClass;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ClassObfuscation 门面：极简 API、契约保留、契约并集合并、跨类引用保护、
 * 版本前置检查、临时文件清理、开关关闭直通。
 */
class ClassObfuscationTest {

    private static byte[] classBytes(Class<?> clazz) throws Exception {
        String resource = clazz.getName().replace('.', '/') + ".class";
        try (InputStream in = clazz.getClassLoader().getResourceAsStream(resource)) {
            assertNotNull(in, "fixture class bytes not found: " + resource);
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) != -1) {
                out.write(tmp, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static Set<String> methodNames(byte[] classBytes) {
        Set<String> names = new LinkedHashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return names;
    }

    private static Set<String> fieldNames(byte[] classBytes) {
        Set<String> names = new LinkedHashSet<>();
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
                names.add(name);
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return names;
    }

    @Test
    void shouldPassThroughWhenDisabled() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        assertArrayEquals(origin, ClassObfuscation.obfuscate(origin, ObfuscationConfig.defaults()));
        assertArrayEquals(origin, ClassObfuscation.obfuscate(origin, (ObfuscationConfig) null));
        assertArrayEquals(origin, ClassObfuscation.obfuscate(origin, "x.y.Z", Opcodes.V1_8,
                ObfuscationTarget.SHELL, ObfuscationConfig.defaults(),
                MethodContracts.CONSERVATIVE, Collections.emptyMap()));
    }

    @Test
    void shouldObfuscateWithSimpleApi() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(origin);
        assertNotNull(output);
        assertNotEquals(origin.length, output.length);
        // 输出可被 ASM 解析，顶层类名保持一致
        ClassReader cr = new ClassReader(output);
        assertEquals(OuterClass.class.getName(), cr.getClassName().replace('/', '.'));
        Set<String> methods = methodNames(output);
        // CONSERVATIVE 契约入口保留
        assertTrue(methods.contains("doFilter"), "contract entry doFilter should survive: " + methods);
        assertTrue(methods.contains("toString"), "toString should survive: " + methods);
        // 非契约方法被改名
        assertFalse(methods.contains("renameMe"), "renameMe should be renamed: " + methods);
        // 字段名混淆生效
        assertFalse(fieldNames(output).contains("sharedField"), "sharedField should be renamed");
    }

    @Test
    void embeddableLimitMatchesBase64ConstantLimit() {
        int max = ClassObfuscation.MAX_EMBEDDABLE_GZIP_SIZE;
        // base64 长度 = 4 * ceil(n / 3)，class 文件 UTF8 常量上限 65535
        assertTrue(4 * ((max + 2) / 3) <= 65535,
                "limit " + max + " encodes to " + (4 * ((max + 2) / 3)) + " chars");
        assertTrue(4 * (((max + 1) + 2) / 3) > 65535,
                "limit must be tight; " + (max + 1) + " bytes should not fit");
    }

    @Test
    void shouldPreserveDeclaredContracts() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(origin, OuterClass.class.getName(), Opcodes.V1_8,
                ObfuscationTarget.SHELL, ObfuscationConfig.enabled(),
                MethodContracts.signatures("outerCall"), Collections.emptyMap());
        Set<String> methods = methodNames(output);
        assertTrue(methods.contains("outerCall"), "declared contract should survive: " + methods);
        assertFalse(methods.contains("renameMe"), "renameMe should be renamed: " + methods);
    }

    @Test
    void shouldMergeUserBlacklistWithContracts() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("methodBlackList", "renameMe");
        byte[] output = ClassObfuscation.obfuscate(origin, OuterClass.class.getName(), Opcodes.V1_8,
                ObfuscationTarget.SHELL, ObfuscationConfig.enabled(options),
                MethodContracts.signatures("outerCall"), Collections.emptyMap());
        Set<String> methods = methodNames(output);
        // 系统契约与用户黑名单并集：两者都存活
        assertTrue(methods.contains("outerCall"), "system contract should survive: " + methods);
        assertTrue(methods.contains("renameMe"), "user blacklist entry should survive: " + methods);
    }

    @Test
    void shouldKeepInjectorToStringWhenAutoDisableImplOff() throws Exception {
        // probe 回显经 injector.toString() 取注入日志；INJECTOR_COMMON 必须在 autoDisableImpl 关闭、
        // 父类 Object 顺带保护失效时仍保住 toString 重写
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("autoDisableImpl", false);
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(origin, OuterClass.class.getName(), Opcodes.V1_8,
                ObfuscationTarget.INJECTOR, ObfuscationConfig.enabled(options),
                MethodContracts.INJECTOR_COMMON, Collections.emptyMap());
        Set<String> methods = methodNames(output);
        assertTrue(methods.contains("toString"), "toString should survive for probe echo: " + methods);
        assertFalse(methods.contains("renameMe"), "renameMe should be renamed: " + methods);
    }

    @Test
    void shouldProtectCrossClassReferences() throws Exception {
        byte[] outer = classBytes(OuterClass.class);
        byte[] helper = classBytes(InnerHelper.class);
        Map<String, byte[]> related = new HashMap<>();
        related.put("helper", helper);
        // 不给任何契约：outerCall 由跨类扫描发现并保护，sharedField 触发字段名混淆自动关闭
        byte[] output = ClassObfuscation.obfuscate(outer, OuterClass.class.getName(), Opcodes.V1_8,
                ObfuscationTarget.INJECTOR, ObfuscationConfig.enabled(),
                Collections.<MethodSignature>emptySet(), related);
        Set<String> methods = methodNames(output);
        assertTrue(methods.contains("outerCall"),
                "method referenced by related class should survive: " + methods);
        assertTrue(fieldNames(output).contains("sharedField"),
                "field accessed by related class should survive (enableFieldName auto off): " + fieldNames(output));
    }

    @Test
    void shouldRejectUnknownOptionKey() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("noSuchOption", true);
        ObfuscationConfig config = ObfuscationConfig.enabled(options);
        assertThrows(GenerationException.class, () -> ClassObfuscation.obfuscate(origin,
                OuterClass.class.getName(), Opcodes.V1_8, ObfuscationTarget.SHELL, config,
                MethodContracts.CONSERVATIVE, Collections.emptyMap()));
    }

    @Test
    void shouldRejectJava15OrBelow() throws Exception {
        byte[] origin = classBytes(OuterClass.class).clone();
        // major version 改写为 49（Java 1.5），前置检查应在解析细节前拦截
        origin[6] = 0;
        origin[7] = 49;
        ObfuscationConfig config = ObfuscationConfig.enabled();
        assertThrows(GenerationException.class, () -> ClassObfuscation.obfuscate(origin,
                OuterClass.class.getName(), Opcodes.V1_6, ObfuscationTarget.SHELL, config,
                MethodContracts.CONSERVATIVE, Collections.emptyMap()));
    }

    @Test
    void shouldNotExceedTargetJreVersion() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(origin, OuterClass.class.getName(), Opcodes.V1_8,
                ObfuscationTarget.SHELL, ObfuscationConfig.enabled(),
                MethodContracts.CONSERVATIVE, Collections.emptyMap());
        int outVersion = new ClassReader(output).readShort(6) & 0xFFFF;
        assertTrue(outVersion <= Opcodes.V1_8, "output major version " + outVersion + " should be <= 52");
    }

    @Test
    void shouldEncryptStaticStringFieldConstants() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(
                origin, OuterClass.class.getName(), Opcodes.V1_8, ObfuscationTarget.SHELL,
                ObfuscationConfig.enabled(), MethodContracts.CONSERVATIVE,
                Collections.<String, byte[]>emptyMap(), false);

        // 常量池里不再残留明文字段常量
        String raw = new String(output, StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(OuterClass.STATIC_SECRET), "static field constant stayed plaintext");
        assertFalse(raw.contains(OuterClass.SECOND_SECRET), "static field constant stayed plaintext");
        assertFalse(hasStringFieldConstant(output, OuterClass.STATIC_SECRET));
        assertFalse(hasStringFieldConstant(output, OuterClass.SECOND_SECRET));

        // 字段名可能已被混淆，按值断言运行期仍能取到原文
        Set<String> values = staticStringFieldValues(output, OuterClass.class.getName());
        assertTrue(values.contains(OuterClass.STATIC_SECRET), "static field value lost: " + values);
        assertTrue(values.contains(OuterClass.SECOND_SECRET), "static field value lost: " + values);
    }

    @Test
    void shouldNotInjectJunkStringSnippets() throws Exception {
        byte[] origin = classBytes(OuterClass.class);
        byte[] output = ClassObfuscation.obfuscate(origin);
        // 花指令会在每个方法调用前插入 new String("random")，即 <init>(Ljava/lang/String;)V
        assertEquals(0, stringCopyConstructorCalls(output),
                "junk code should not be injected by the STRONG profile");
    }

    private static boolean hasStringFieldConstant(byte[] classBytes, String expectedValue) {
        final boolean[] found = new boolean[1];
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object value) {
                if (expectedValue.equals(value)) {
                    found[0] = true;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE);
        return found[0];
    }

    private static int stringCopyConstructorCalls(byte[] classBytes) {
        final int[] count = new int[1];
        new ClassReader(classBytes).accept(new ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(org.objectweb.asm.Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String methodName,
                                                String methodDescriptor, boolean isInterface) {
                        if (opcode == Opcodes.INVOKESPECIAL && "java/lang/String".equals(owner)
                                && "<init>".equals(methodName)
                                && "(Ljava/lang/String;)V".equals(methodDescriptor)) {
                            count[0]++;
                        }
                    }
                };
            }
        }, 0);
        return count[0];
    }

    private static Set<String> staticStringFieldValues(byte[] classBytes, String className) throws Exception {
        ClassLoader loader = new SingleClassLoader(className, classBytes);
        Class<?> clazz = loader.loadClass(className);
        Set<String> values = new LinkedHashSet<>();
        for (Field field : clazz.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                field.setAccessible(true);
                Object value = field.get(null);
                if (value != null) {
                    values.add((String) value);
                }
            }
        }
        return values;
    }

    private static final class SingleClassLoader extends ClassLoader {
        private final String className;
        private final byte[] classBytes;

        private SingleClassLoader(String className, byte[] classBytes) {
            super(null);
            this.className = className;
            this.classBytes = classBytes;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!className.equals(name)) {
                return super.loadClass(name, resolve);
            }
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                loaded = defineClass(name, classBytes, 0, classBytes.length);
            }
            if (resolve) {
                resolveClass(loaded);
            }
            return loaded;
        }
    }

    @Test
    void shouldLeaveNoTempFilesBehind() throws Exception {
        Path cwd = Paths.get(".").toAbsolutePath().normalize();
        byte[] origin = classBytes(OuterClass.class);
        ClassObfuscation.obfuscate(origin);
        assertFalse(Files.exists(cwd.resolve("class-obf-temp.class")), "class-obf-temp.class should be cleaned");
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(cwd, "class-obf*.class")) {
            assertFalse(stream.iterator().hasNext(), "class-obf*.class should be cleaned");
        }
        assertFalse(Files.exists(cwd.resolve("class-obf-lib")), "empty class-obf-lib dir should be cleaned");
        Path tmp = Paths.get(System.getProperty("java.io.tmpdir"));
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tmp, "memshell-party-obf-*")) {
            assertFalse(stream.iterator().hasNext(), "memshell-party-obf-* work dirs should be cleaned");
        }
    }
}
