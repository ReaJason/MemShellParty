package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.BytecodeClassResponse;
import com.reajason.javaweb.boot.dto.BytecodeTransformRequest;
import com.reajason.javaweb.boot.dto.BytecodeTransformResponse;
import com.reajason.javaweb.asm.ClassBytesEncoder;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.packer.PackerSupport;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BytecodeTransformServiceTest {
    private final BytecodeTransformService service = new BytecodeTransformService();
    private byte[] classBytes;
    private String className;

    @BeforeEach
    void readFixture() throws Exception {
        className = Payload.class.getName();
        classBytes = readClassFile(Payload.class);
    }

    private static byte[] readClassFile(Class<?> type) throws Exception {
        String binaryName = type.getName();
        InputStream in = type.getResourceAsStream(
                binaryName.substring(binaryName.lastIndexOf('.') + 1) + ".class");
        assertNotNull(in);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    @Test
    void decodeNormalizesGzipBase64ForBrowserPreview() {
        String gzipBase64 = ClassBytesEncoder.encode(classBytes, true);

        BytecodeClassResponse response = service.decode(gzipBase64);

        assertEquals(className, response.getClassName());
        assertEquals(classBytes.length, response.getSize());
        assertArrayEquals(classBytes, Base64.getDecoder().decode(response.getClassBytesBase64Str()));
    }

    @Test
    void doesNotRandomizeClassNameByDefault() {
        BytecodeTransformRequest request = request();
        request.setShrink(false);

        BytecodeTransformResponse response = service.transform(request);

        assertEquals(className, response.getClassName());
        assertArrayEquals(classBytes, Base64.getDecoder().decode(response.getClassBytesBase64Str()));
    }

    @Test
    void randomizesEntireClassName() {
        BytecodeTransformRequest request = request();
        request.setRandomName(true);

        BytecodeTransformResponse response = service.transform(request);

        String originalPackage = className.substring(0, className.lastIndexOf('.') + 1);
        assertFalse(response.getClassName().startsWith(originalPackage));
        assertNotEquals(className, response.getClassName());
        String simpleName = response.getClassName().substring(response.getClassName().lastIndexOf('.') + 1);
        assertTrue(simpleName.matches("[A-Z][A-Za-z0-9]*Utils"), response.getClassName());
    }

    @Test
    void renamesToExplicitFullName() {
        BytecodeTransformRequest request = request();
        request.setNewClassName("com.example.generated.Renamed");

        BytecodeTransformResponse response = service.transform(request);

        assertEquals("com.example.generated.Renamed", response.getClassName());
    }

    @Test
    void convertCanPackTransformedClass() {
        BytecodeTransformRequest request = request();
        request.setNewClassName("RenamedPayload");
        request.setShrink(true);

        BytecodeTransformResponse response = service.transform(request);

        assertEquals(className.substring(0, className.lastIndexOf('.') + 1) + "RenamedPayload",
                response.getClassName());
        assertNotEquals(Base64.getEncoder().encodeToString(classBytes), response.getClassBytesBase64Str());
        assertEquals(response.getClassBytesBase64Str(), response.getPackResult());
    }

    @Test
    void springGzipJdk17PackerRepairsFinalClassPackage() {
        BytecodeTransformRequest request = request();
        request.setPacker(Packers.SpELSpringGzipJDK17);
        request.setNewClassName("RenamedPayload");

        BytecodeTransformResponse response = service.transform(request);

        assertTrue(PackerSupport.isSpringExpressionClassName(response.getClassName()),
                response.getClassName());
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        assertEquals(response.getClassName(), new ClassReader(transformed).getClassName().replace('/', '.'));
        assertTrue(response.getPackResult().contains(response.getClassName()));
    }

    @Test
    void spelPackerDisablesObfuscationBeforePacking() {
        BytecodeTransformRequest request = request();
        request.setPacker(Packers.SpELSpringGzip);
        request.setObfuscation(ObfuscationConfig.enabled());

        BytecodeTransformResponse response = service.transform(request);

        assertFalse(request.getObfuscation().isEnabled());
        assertTrue(response.getPackResult().length() <= 10000,
                "关闭混淆后的表达式应满足 SpEL 长度上限");
    }

    @Test
    void obfuscatesTransformedClassWithCustomOptions() {
        BytecodeTransformRequest request = request();
        request.setShrink(false);
        request.setObfuscation(ObfuscationConfig.enabled(
                Collections.<String, Object>singletonMap("methodBlackList", "keepMe")));

        BytecodeTransformResponse response = service.transform(request);
        ClassInspection inspection = inspect(Base64.getDecoder().decode(response.getClassBytesBase64Str()));

        assertEquals(className, response.getClassName());
        assertTrue(inspection.methodNames.contains("keepMe"), "自定义方法黑名单应保留");
        assertFalse(inspection.methodNames.contains("renameMe"), "普通方法应被混淆改名");
        assertTrue(inspection.methodNames.contains("toString"), "保守契约入口应保留");
    }

    @Test
    void wrapsTransformedClassForSelectedProbeServer() {
        BytecodeTransformRequest request = request();
        request.setShrink(false);
        request.setServer("Tomcat");
        request.setProbe(ProbeConfig.builder().probeMethod(ProbeMethod.ResponseBody).build());

        BytecodeTransformResponse response = service.transform(request);

        assertEquals(className + "Wrapper", response.getClassName());
        byte[] wrapperBytes = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        assertEquals(response.getClassBytesBase64Str(), response.getPackResult());
        String[] embeddedBase64 = new String[1];
        new ClassReader(wrapperBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String && ((String) value).startsWith("H4sI")) {
                            embeddedBase64[0] = (String) value;
                        }
                    }
                };
            }
        }, 0);
        assertNotNull(embeddedBase64[0], "回显 Wrapper 应内嵌 gzip + Base64 的原始类");
        assertArrayEquals(classBytes,
                CommonUtil.gzipDecompress(Base64Utils.decodeBase64(embeddedBase64[0])));
    }

    @Test
    void generatesResponseHeaderNameForProbeWrapper() {
        BytecodeTransformRequest request = request();
        request.setServer("Jetty");
        request.setProbe(ProbeConfig.builder().probeMethod(ProbeMethod.ResponseHeader).build());

        BytecodeTransformResponse response = service.transform(request);

        assertEquals(className + "Wrapper", response.getClassName());
        assertTrue(request.getProbe().getRespHeaderName().startsWith("X-"));
    }

    @Test
    void renamesPackageWhenEnabled() {
        BytecodeTransformRequest request = request();
        request.setNewClassName(className);
        request.setRenamePackage(true);
        request.setRelocateFrom("com.reajason.javaweb.boot");
        request.setRelocateTo("example.renamed");

        BytecodeTransformResponse response = service.transform(request);

        assertEquals("example.renamed.service.BytecodeTransformServiceTest$Payload", response.getClassName());
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        assertEquals("example/renamed/service/BytecodeTransformServiceTest$Payload",
                new ClassReader(transformed).getClassName());
    }

    @Test
    void ignoresPackagePrefixesWhenRenameIsDisabled() {
        BytecodeTransformRequest request = request();
        request.setRelocateFrom("com.reajason");
        request.setRelocateTo("example.renamed");
        request.setShrink(false);

        BytecodeTransformResponse response = service.transform(request);

        assertEquals(className, response.getClassName());
        assertArrayEquals(classBytes, Base64.getDecoder().decode(response.getClassBytesBase64Str()));
    }

    @Test
    void requiresBothPackagePrefixesWhenRenameIsEnabled() {
        String[][] invalidPrefixes = {
                {null, null},
                {"com.reajason", null},
                {null, "example.renamed"},
                {" ", "\t"}
        };
        for (String[] prefixes : invalidPrefixes) {
            BytecodeTransformRequest request = request();
            request.setRenamePackage(true);
            request.setRelocateFrom(prefixes[0]);
            request.setRelocateTo(prefixes[1]);

            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> service.transform(request));
            assertEquals("包名重命名需要同时填写原包名前缀与新包名前缀", error.getMessage());
        }
    }

    @Test
    void appliesBytecodeOptionsTogether() throws Exception {
        BytecodeTransformRequest request = request();
        request.setNewClassName("RenamedPayload");
        request.setByPassJavaModule(true);
        request.setStaticInitialize(true);
        request.setShrink(true);

        BytecodeTransformResponse response = service.transform(request);
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        ClassInspection inspection = inspect(transformed);

        assertEquals(className.substring(0, className.lastIndexOf('.') + 1) + "RenamedPayload",
                response.getClassName());
        assertTrue(inspection.clinitInstantiatesRenamedClass, "静态初始化应实例化改名后的类");
        assertNull(inspection.sourceFile, "缩小字节码应清除 SourceFile");

        ClassLoader loader = new ClassLoader(Payload.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (response.getClassName().equals(name)) {
                    return defineClass(name, transformed, 0, transformed.length);
                }
                return super.findClass(name);
            }
        };
        Class<?> transformedType = Class.forName(response.getClassName(), true, loader);
        assertEquals(Object.class.getModule(), transformedType.getModule(),
                "静态初始化应把当前类的 module 改成 java.base");
    }

    @Test
    void bypassesModuleWithoutStaticTrigger() throws Exception {
        BytecodeTransformRequest request = request();
        request.setNewClassName("RenamedPayload");
        request.setByPassJavaModule(true);
        request.setShrink(false);

        BytecodeTransformResponse response = service.transform(request);
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        ClassLoader loader = new ClassLoader(Payload.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (response.getClassName().equals(name)) {
                    return defineClass(name, transformed, 0, transformed.length);
                }
                return super.findClass(name);
            }
        };
        Class<?> transformedType = Class.forName(response.getClassName(), true, loader);

        assertEquals(Object.class.getModule(), transformedType.getModule(),
                "没有静态初始化块时也应补出 <clinit> 执行模块绕过");
    }

    @Test
    void rejectsInvalidNewClassName() {
        BytecodeTransformRequest request = request();
        request.setNewClassName("1Bad");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> service.transform(request));

        assertTrue(error.getMessage().contains("不是合法的类名"), error.getMessage());
    }

    @Test
    void rejectsStaticTriggerWithoutNoArgConstructor() throws Exception {
        BytecodeTransformRequest request = new BytecodeTransformRequest();
        request.setClassBytesBase64(Base64.getEncoder().encodeToString(readClassFile(
                StringConstructorOnly.class)));
        request.setPacker(Packers.DefaultBase64);
        request.setStaticInitialize(true);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> service.transform(request));

        assertTrue(error.getMessage().contains("无参构造方法"), error.getMessage());
    }

    @Test
    void addsEntryAfterClassNameAndPackageChanges() throws Exception {
        BytecodeTransformRequest request = request();
        request.setNewClassName("RenamedPayload");
        request.setRenamePackage(true);
        request.setRelocateFrom("com.reajason.javaweb.boot");
        request.setRelocateTo("example.renamed");
        request.setEntryMethod("public static String exec(String value)");

        BytecodeTransformResponse response = service.transform(request);
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        ClassLoader loader = new ClassLoader(Payload.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (response.getClassName().equals(name)) {
                    return defineClass(name, transformed, 0, transformed.length);
                }
                return super.findClass(name);
            }
        };
        Class<?> transformedType = Class.forName(response.getClassName(), true, loader);

        assertEquals("example.renamed.service.RenamedPayload", response.getClassName());
        assertEquals("payload", transformedType.getMethod("exec", String.class)
                .invoke(null, "ignored"));
    }

    @Test
    void addsEntryToProbeWrapperInsteadOfEmbeddedClass() throws Exception {
        BytecodeTransformRequest request = request();
        request.setServer("Tomcat");
        request.setProbe(ProbeConfig.builder().probeMethod(ProbeMethod.ResponseBody).build());
        request.setEntryMethod("public static String exec(String value)");

        BytecodeTransformResponse response = service.transform(request);
        byte[] transformed = Base64.getDecoder().decode(response.getClassBytesBase64Str());
        ClassLoader loader = new ClassLoader(Payload.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (response.getClassName().equals(name)) {
                    return defineClass(name, transformed, 0, transformed.length);
                }
                return super.findClass(name);
            }
        };
        Class<?> transformedType = Class.forName(response.getClassName(), true, loader);

        assertEquals(className + "Wrapper", response.getClassName());
        assertNotNull(transformedType.getMethod("exec", String.class)
                .invoke(null, "ignored"));
    }

    @Test
    void rejectsFullMemShellOnlyPacker() {
        BytecodeTransformRequest request = request();
        request.setPacker(Packers.FilelessAgent);

        UnsupportedOperationException error = assertThrows(UnsupportedOperationException.class,
                () -> service.transform(request));
        assertTrue(error.getMessage().contains("独立 class"));
    }

    @Test
    void rejectsInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> service.decode("not base64"));
    }

    private BytecodeTransformRequest request() {
        BytecodeTransformRequest request = new BytecodeTransformRequest();
        request.setClassBytesBase64(Base64.getEncoder().encodeToString(classBytes));
        request.setPacker(Packers.DefaultBase64);
        return request;
    }

    private static ClassInspection inspect(byte[] bytes) {
        ClassInspection inspection = new ClassInspection();
        String originalOwner = classInternalName(Payload.class);
        String renamedOwner = originalOwner.substring(0, originalOwner.lastIndexOf('/') + 1)
                + "RenamedPayload";
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(String source, String debug) {
                inspection.sourceFile = source;
            }

            @Override
            public MethodVisitor visitMethod(int access, String methodName, String descriptor,
                                             String signature, String[] exceptions) {
                inspection.methodNames.add(methodName);
                if (!"<clinit>".equals(methodName)) {
                    return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        if (opcode == Opcodes.NEW && renamedOwner.equals(type)) {
                            inspection.clinitInstantiatesRenamedClass = true;
                        }
                    }
                };
            }
        }, 0);
        return inspection;
    }

    private static String classInternalName(Class<?> type) {
        return type.getName().replace('.', '/');
    }

    private static final class ClassInspection {
        private final Set<String> methodNames = new LinkedHashSet<>();
        private boolean clinitInstantiatesRenamedClass;
        private String sourceFile;
    }

    public static class Payload {
        public Payload() {
        }

        public String keepMe() {
            return "keep";
        }

        public String renameMe() {
            return "rename";
        }

        @Override
        public String toString() {
            return "payload";
        }
    }

    public static class StringConstructorOnly {
        public StringConstructorOnly(String value) {
        }
    }
}
