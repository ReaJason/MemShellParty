package com.reajason.javaweb.packer.jar.agent;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.fileless.FilelessAgentBootstrap;
import com.reajason.javaweb.fileless.JarLoader;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.JarPacker;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilelessAgentPackerTest {

    @Test
    void packsOneJava6BootstrapClassWithSelfContainedAgentPayload() throws Exception {
        String agentClassName = "fixture.packed.FilelessAgent";
        byte[] delivered = Base64.getDecoder().decode(new FilelessAgentPacker().pack(result(agentClassName)));
        ClassReader bootstrapReader = new ClassReader(delivered);
        String bootstrapName = bootstrapReader.getClassName();

        assertEquals(50, bootstrapReader.readShort(6));
        assertTrue((bootstrapReader.getAccess() & Opcodes.ACC_PUBLIC) != 0);
        assertFalse(bootstrapName.startsWith("com/reajason/"), bootstrapName);
        assertTrue(bootstrapName.endsWith("/FilelessAgentBootstrap"), bootstrapName);
        assertNotEquals("com/reajason/javaweb/fileless/FilelessAgentBootstrap", bootstrapName);
        assertFalse(JarPacker.class.isAssignableFrom(FilelessAgentPacker.class));

        Class<?> bootstrap = new SingleClassLoader(getClass().getClassLoader()).define(delivered);
        assertEquals(bootstrapName.replace('/', '.'), bootstrap.getName());
        assertNotNull(bootstrap.getConstructor());

        Payload payload = readPayload(delivered);
        assertEquals("InstrumentationProvider", simpleName(payload.classes.keySet().iterator().next()));
        assertFalse(payload.classes.containsKey(bootstrapName.replace('/', '.')));
        assertTrue(hasClass(payload, "JarLoader"));
        assertTrue(hasClass(payload, "JarLoader$MemoryURLStreamHandler"));
        assertTrue(hasClass(payload, "JarLoader$MemoryURLConnection"));
        List<String> runtimeOrder = new ArrayList<>();
        for (String className : payload.classes.keySet()) {
            runtimeOrder.add(simpleName(className));
        }
        assertTrue(runtimeOrder.indexOf("JarLoader$MemoryURLConnection")
                < runtimeOrder.indexOf("JarLoader$MemoryURLStreamHandler"));
        assertTrue(runtimeOrder.indexOf("JarLoader$MemoryURLStreamHandler")
                < runtimeOrder.indexOf("JarLoader"));
        assertTrue(hasClass(payload, "HotSpotProfileProvider"));
        assertTrue(hasClass(payload, "Elf64File"));
        assertTrue(hasClass(payload, "LinuxAcquisitionResolver"));
        assertTrue(hasClass(payload, "LinuxInstrumentationProvider"));
        assertTrue(hasClass(payload, "NativeImage"));
        assertTrue(hasClass(payload, "X86_64JPLISLayout"));
        assertTrue(hasClass(payload, "X86_64StrippedJPLIS"));
        assertTrue(hasClass(payload, "X86_64NativeStub"));
        assertTrue(hasClass(payload, "AArch64JPLISLayout"));
        assertTrue(hasClass(payload, "AArch64NativeStub"));
        assertFalse(hasClass(payload, "JvmProfile"));
        assertFalse(hasClass(payload, "NativeLibraryFingerprint"));
        assertTrue(payload.classes.size() < 256);
        for (Map.Entry<String, byte[]> entry : payload.classes.entrySet()) {
            assertTrue(entry.getKey().startsWith(bootstrapName.substring(0, bootstrapName.lastIndexOf('/')).replace('/', '.')));
            assertFalse(entry.getKey().startsWith("com.reajason."), entry.getKey());
            ClassReader runtimeClass = new ClassReader(entry.getValue());
            assertEquals(entry.getKey().replace('.', '/'), runtimeClass.getClassName(), entry.getKey());
            assertFalse(runtimeClass.getClassName().startsWith("com/reajason/"), entry.getKey());
            assertEquals(50, runtimeClass.readShort(6), entry.getKey());
        }

        JarContents jar = readJar(payload.agentJar);
        assertEquals(agentClassName, jar.manifest.getMainAttributes().getValue("Agent-Class"));
        assertEquals(agentClassName, jar.manifest.getMainAttributes().getValue("Premain-Class"));
        assertEquals("1", jar.manifest.getMainAttributes().getValue("Fileless-Agent-Contract"));
        byte[] packedAgentBytes = jar.entries.get(agentClassName.replace('.', '/') + ".class");
        assertNotNull(packedAgentBytes);
        assertEquals(50, new ClassReader(packedAgentBytes).readShort(6));

        Instrumentation instrumentation = capableInstrumentation();
        ClassLoader loader = FilelessAgentBootstrap.install(payload.agentJar, "packed-agent-args",
                instrumentation, getClass().getClassLoader());
        assertTrue(loader instanceof JarLoader);
        assertSame(loader, loader.loadClass(agentClassName).getClassLoader());
        assertEquals("packed-agent-args", PackedAgentLog.args);
        assertSame(instrumentation, PackedAgentLog.instrumentation);
        assertSame(loader, PackedAgentLog.contextClassLoader);
    }

    @Test
    void isolatesEveryDeliveryInTheSameServletClassLoader() throws Exception {
        FilelessAgentPacker packer = new FilelessAgentPacker();
        MemShellResult result = result("fixture.packed.RepeatedAgent");
        byte[] first = Base64.getDecoder().decode(packer.pack(result));
        byte[] second = Base64.getDecoder().decode(packer.pack(result));
        SingleClassLoader loader = new SingleClassLoader(getClass().getClassLoader());

        Class<?> firstClass = loader.define(first);
        Class<?> secondClass = loader.define(second);

        assertNotEquals(firstClass.getName(), secondClass.getName());
        assertSame(loader, firstClass.getClassLoader());
        assertSame(loader, secondClass.getClassLoader());
    }

    @Test
    void constructorDefinesEmbeddedRuntimeBeforeUnknownProfileFailsClosed() throws Exception {
        byte[] delivered = Base64.getDecoder().decode(
                new FilelessAgentPacker().pack(result("fixture.packed.UnknownProfileAgent")));
        Class<?> bootstrap = new SingleClassLoader(getClass().getClassLoader()).define(delivered);
        String originalVendor = System.getProperty("java.vendor");
        try {
            System.setProperty("java.vendor", "FilelessAgentPackerTest-Unsupported");
            InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                    () -> bootstrap.getConstructor().newInstance());
            Throwable cause = failure.getCause();
            assertTrue(cause instanceof UnsupportedOperationException, String.valueOf(cause));
            assertTrue(cause.getMessage().contains("native state was not changed"), cause.getMessage());
        } finally {
            if (originalVendor == null) {
                System.clearProperty("java.vendor");
            } else {
                System.setProperty("java.vendor", originalVendor);
            }
        }
    }

    @Test
    void rejectsNonAgentResults() throws IOException {
        MemShellResult result = result("fixture.packed.NotAnAgent");
        result.getShellConfig().setShellType(ShellType.FILTER);

        assertThrows(IllegalArgumentException.class, () -> new FilelessAgentPacker().pack(result));
    }

    private static MemShellResult result(String agentClassName) throws IOException {
        byte[] agent = ClassRenameUtils.renameClass(readClass(PackedAgentFixture.class), agentClassName);
        String shellClassName = agentClassName + "Shell";
        byte[] shell = ClassRenameUtils.renameClass(readClass(PackedAgentFixture.class), shellClassName);
        return MemShellResult.builder()
                .shellClassName(shellClassName)
                .shellBytes(shell)
                .injectorClassName(agentClassName)
                .injectorBytes(agent)
                .shellConfig(ShellConfig.builder().shellType(ShellType.AGENT).build())
                .build();
    }

    private static Payload readPayload(byte[] bootstrap) throws IOException {
        List<String> chunks = new ArrayList<>();
        new ClassReader(bootstrap).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                if (!"payloadChunks".equals(name) || !"()[Ljava/lang/String;".equals(descriptor)) {
                    return null;
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            chunks.add((String) value);
                        }
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        assertFalse(chunks.isEmpty());
        StringBuilder encoded = new StringBuilder();
        for (String chunk : chunks) {
            assertTrue(chunk.length() > 0 && chunk.length() <= 60000);
            encoded.append(chunk);
        }
        DataInputStream input = new DataInputStream(new GZIPInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(encoded.toString()))));
        try {
            assertEquals(0x464c4131, input.readInt());
            int count = input.readInt();
            assertTrue(count > 0 && count <= 256);
            Map<String, byte[]> classes = new LinkedHashMap<>();
            for (int i = 0; i < count; i++) {
                classes.put(input.readUTF(), readEntry(input));
            }
            byte[] agentJar = readEntry(input);
            assertEquals(-1, input.read());
            return new Payload(classes, agentJar);
        } finally {
            input.close();
        }
    }

    private static boolean hasClass(Payload payload, String simpleName) {
        for (String name : payload.classes.keySet()) {
            if (simpleName(name).equals(simpleName)) {
                return true;
            }
        }
        return false;
    }

    private static String simpleName(String className) {
        return className.substring(className.lastIndexOf('.') + 1);
    }

    private static Instrumentation capableInstrumentation() {
        return (Instrumentation) Proxy.newProxyInstance(
                FilelessAgentPackerTest.class.getClassLoader(),
                new Class<?>[]{Instrumentation.class}, new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        if ("isRedefineClassesSupported".equals(method.getName())
                                || "isRetransformClassesSupported".equals(method.getName())) {
                            return true;
                        }
                        throw new AssertionError("Unexpected Instrumentation call: " + method);
                    }
                });
    }

    private static byte[] readClass(Class<?> type) throws IOException {
        String resource = type.getName().replace('.', '/') + ".class";
        InputStream input = type.getClassLoader().getResourceAsStream(resource);
        if (input == null) {
            throw new IOException("Missing " + resource);
        }
        try {
            return readBytes(input);
        } finally {
            input.close();
        }
    }

    private static JarContents readJar(byte[] bytes) throws IOException {
        JarInputStream input = new JarInputStream(new ByteArrayInputStream(bytes));
        try {
            Manifest manifest = input.getManifest();
            Map<String, byte[]> entries = new LinkedHashMap<>();
            JarEntry entry;
            while ((entry = input.getNextJarEntry()) != null) {
                if (!entry.isDirectory()) {
                    entries.put(entry.getName(), readBytes(input));
                }
            }
            return new JarContents(manifest, entries);
        } finally {
            input.close();
        }
    }

    private static byte[] readEntry(DataInputStream input) throws IOException {
        int length = input.readInt();
        assertTrue(length > 0 && length <= 128 * 1024 * 1024);
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return bytes;
    }

    private static byte[] readBytes(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int length;
        while ((length = input.read(buffer)) != -1) {
            output.write(buffer, 0, length);
        }
        return output.toByteArray();
    }

    private static final class SingleClassLoader extends ClassLoader {
        private SingleClassLoader(ClassLoader parent) {
            super(parent);
        }

        private Class<?> define(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }

    private static final class Payload {
        private final Map<String, byte[]> classes;
        private final byte[] agentJar;

        private Payload(Map<String, byte[]> classes, byte[] agentJar) {
            this.classes = classes;
            this.agentJar = agentJar;
        }
    }

    private static final class JarContents {
        private final Manifest manifest;
        private final Map<String, byte[]> entries;

        private JarContents(Manifest manifest, Map<String, byte[]> entries) {
            this.manifest = manifest;
            this.entries = entries;
        }
    }
}
