package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.BytecodeClassResponse;
import com.reajason.javaweb.boot.dto.BytecodeTransformRequest;
import com.reajason.javaweb.boot.dto.BytecodeTransformResponse;
import com.reajason.javaweb.bytecode.ClassBytesEncoder;
import com.reajason.javaweb.packer.Packers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
        InputStream in = Payload.class.getResourceAsStream("BytecodeTransformServiceTest$Payload.class");
        assertNotNull(in);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            classBytes = out.toByteArray();
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
        assertTrue(inspection.hasModuleHelper, "应添加模块绕过辅助方法");
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
        Class.forName(response.getClassName(), true, loader);
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
                if (methodName.startsWith("$msp$")) {
                    inspection.hasModuleHelper = true;
                }
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
        private boolean hasModuleHelper;
        private boolean clinitInstantiatesRenamedClass;
        private String sourceFile;
    }

    public static class Payload {
        public Payload() {
        }

        @Override
        public String toString() {
            return "payload";
        }
    }
}
