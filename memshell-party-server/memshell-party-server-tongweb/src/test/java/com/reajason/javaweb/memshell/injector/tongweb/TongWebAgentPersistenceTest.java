package com.reajason.javaweb.memshell.injector.tongweb;

import com.reajason.javaweb.agent.AgentPersistence;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class TongWebAgentPersistenceTest {
    private static final String[] TARGET_PACKAGES = new String[]{
            "com/tongweb/web/thor/core/",
            "com/tongweb/catalina/core/",
            "com/tongweb/server/core/",
            "com/tongweb/container/core/"
    };

    @TempDir
    Path tempDir;

    @Test
    void allFilterChainVariantsPersistIntoJar() throws Exception {
        for (String targetPackage : TARGET_PACKAGES) {
            assertPersistence(targetPackage + "ApplicationFilterChain", "doFilter",
                    ShellType.AGENT_FILTER_CHAIN, TongWebFilterChainAgentInjector.class);
        }
    }

    @Test
    void allContextValveVariantsPersistIntoJar() throws Exception {
        for (String targetPackage : TARGET_PACKAGES) {
            assertPersistence(targetPackage + "StandardContextValve", "invoke",
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE, TongWebContextValveAgentInjector.class);
        }
    }

    @Test
    void persistArgumentIsOptIn() {
        assertFalse(TongWebFilterChainAgentInjector.isPersistent(null));
        assertFalse(TongWebFilterChainAgentInjector.isPersistent("persist=false"));
        assertTrue(TongWebFilterChainAgentInjector.isPersistent("persist=true"));
        assertTrue(TongWebContextValveAgentInjector.isPersistent("other=value, persist=true"));
    }

    private void assertPersistence(String targetInternalName, String targetMethodName,
                                   String shellType, Class<?> injectorTemplateClass) throws Exception {
        String targetSimpleName = targetInternalName.substring(targetInternalName.lastIndexOf('/') + 1);
        String shellClassName = "test.TongWeb" + targetSimpleName + "Shell";
        String injectorClassName = "test.TongWeb" + targetSimpleName + "Agent";
        byte[] shellClassBytes = shellClass(shellClassName.replace('.', '/'));
        String jarName = "tongweb-persistence-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        Path agentJar = tempDir.resolve("tongweb-agent-" + UUID.randomUUID() + ".jar");
        Path expectedBackup = Paths.get("/tmp").resolve(jarName + ".bak");
        try {
            writeJar(originalJar, targetInternalName + ".class", targetClass(targetInternalName, targetMethodName));
            byte[] originalJarBytes = Files.readAllBytes(originalJar);
            writeGeneratedAgent(agentJar, injectorClassName, shellClassName, shellClassBytes, shellType, injectorTemplateClass);
            try (JarFile generatedJar = new JarFile(agentJar.toFile())) {
                assertNotNull(generatedJar.getJarEntry(AgentPersistence.class.getName().replace('.', '/') + ".class"));
                assertNotNull(generatedJar.getJarEntry(AgentPersistence.Transformer.class.getName().replace('.', '/') + ".class"));
            }

            Class<?> originalTargetClass;
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                originalTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = originalTargetClass.newInstance();
                originalTargetClass.getMethod(targetMethodName).invoke(target);
                assertTrue(originalTargetClass.getField("invoked").getBoolean(null));
            }
            assertEquals(expectedBackup.toFile(), invokePersist(agentJar, injectorClassName, originalTargetClass));
            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
            byte[] persistedJarBytes = Files.readAllBytes(originalJar);
            try (JarFile persistedJar = new JarFile(originalJar.toFile())) {
                assertArrayEquals(shellClassBytes, readEntry(persistedJar, shellClassName.replace('.', '/') + ".class"));
                assertArrayEquals("keep".getBytes("UTF-8"), readEntry(persistedJar, "application.txt"));
            }
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                Class<?> persistedTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = persistedTargetClass.newInstance();
                persistedTargetClass.getMethod(targetMethodName).invoke(target);
                assertFalse(persistedTargetClass.getField("invoked").getBoolean(null));
            }

            InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                    () -> invokePersist(agentJar, injectorClassName, originalTargetClass));
            assertTrue(failure.getCause() instanceof IllegalStateException);
            assertArrayEquals(persistedJarBytes, Files.readAllBytes(originalJar));
            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
        } finally {
            Files.deleteIfExists(expectedBackup);
        }
    }

    private static File invokePersist(Path agentJar, String injectorClassName, Class<?> targetClass) throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{agentJar.toUri().toURL()},
                TongWebAgentPersistenceTest.class.getClassLoader())) {
            Class<?> injectorClass = loader.loadClass(injectorClassName);
            Method persist = injectorClass.getDeclaredMethod("persist", Class.class);
            persist.setAccessible(true);
            return (File) persist.invoke(null, targetClass);
        }
    }

    private static void writeGeneratedAgent(Path agentJar, String injectorClassName, String shellClassName,
                                            byte[] shellClassBytes, String shellType,
                                            Class<?> injectorTemplateClass) throws IOException {
        InjectorConfig config = InjectorConfig.builder()
                .shellClassBytes(shellClassBytes)
                .shellClassName(shellClassName)
                .injectorClassName(injectorClassName)
                .injectorTemplateClassName(injectorTemplateClass.getName())
                .injectorTemplateClassLoader(injectorTemplateClass.getClassLoader())
                .build();
        InjectorGenerator generator = new InjectorGenerator(ShellConfig.builder().shellType(shellType).build(), config);
        Map<String, byte[]> classes = new HashMap<>();
        classes.put(injectorClassName, generator.generate());
        classes.putAll(generator.getInnerClassBytes());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(agentJar))) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                output.putNextEntry(new JarEntry(entry.getKey().replace('.', '/') + ".class"));
                output.write(entry.getValue());
                output.closeEntry();
            }
        }
    }

    private static void writeJar(Path jarPath, String targetEntryName, byte[] targetClassBytes) throws IOException {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath))) {
            output.putNextEntry(new JarEntry(targetEntryName));
            output.write(targetClassBytes);
            output.closeEntry();
            output.putNextEntry(new JarEntry("application.txt"));
            output.write("keep".getBytes("UTF-8"));
            output.closeEntry();
        }
    }

    private static byte[] readEntry(JarFile jarFile, String entryName) throws IOException {
        JarEntry entry = jarFile.getJarEntry(entryName);
        assertNotNull(entry, entryName);
        try (InputStream input = jarFile.getInputStream(entry)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = input.read(buffer)) != -1) {
                output.write(buffer, 0, length);
            }
            return output.toByteArray();
        }
    }

    private static byte[] targetClass(String internalName, String methodName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "invoked", "Z", null, null).visitEnd();
        defaultConstructor(writer);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_1);
        method.visitFieldInsn(Opcodes.PUTSTATIC, internalName, "invoked", "Z");
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] shellClass(String internalName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null);
        defaultConstructor(writer);
        MethodVisitor equals = writer.visitMethod(Opcodes.ACC_PUBLIC, "equals", "(Ljava/lang/Object;)Z", null, null);
        equals.visitCode();
        equals.visitInsn(Opcodes.ICONST_1);
        equals.visitInsn(Opcodes.IRETURN);
        equals.visitMaxs(0, 0);
        equals.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void defaultConstructor(ClassWriter writer) {
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
    }
}
