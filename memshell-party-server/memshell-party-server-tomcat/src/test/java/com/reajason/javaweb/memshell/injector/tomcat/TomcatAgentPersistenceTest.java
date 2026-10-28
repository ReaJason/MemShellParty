package com.reajason.javaweb.memshell.injector.tomcat;

import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.ShellType;
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
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class TomcatAgentPersistenceTest {
    @TempDir
    Path tempDir;

    @Test
    void filterChainPersistsIntoJarAndKeepsPristineBackup() throws Exception {
        assertPersistence("org/apache/catalina/core/ApplicationFilterChain", "doFilter",
                TomcatFilterChainAgentInjector::persist);
    }

    @Test
    void contextValvePersistsIntoJarAndKeepsPristineBackup() throws Exception {
        assertPersistence("org/apache/catalina/core/StandardContextValve", "invoke",
                TomcatContextValveAgentInjector::persist);
    }

    @Test
    void generatedAgentPersistsWithGeneratedShellNameAndBytes() throws Exception {
        String targetInternalName = "org/apache/catalina/core/ApplicationFilterChain";
        String shellClassName = "test.GeneratedPersistedShell";
        String injectorClassName = "test.GeneratedPersistenceAgent";
        byte[] originalTargetBytes = targetClass(targetInternalName, "doFilter");
        byte[] shellClassBytes = shellClass(shellClassName.replace('.', '/'));
        String jarName = "tomcat-generated-persistence-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        Path expectedBackup = Paths.get("/tmp").resolve(jarName + ".bak");
        try {
            writeJar(originalJar, targetInternalName + ".class", originalTargetBytes);
            byte[] originalJarBytes = Files.readAllBytes(originalJar);
            Path agentJar = tempDir.resolve("generated-agent.jar");
            writeGeneratedAgent(agentJar, injectorClassName, shellClassName, shellClassBytes);
            Class<?> originalTargetClass;
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                originalTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
            }
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{agentJar.toUri().toURL()},
                    TomcatAgentPersistenceTest.class.getClassLoader())) {
                Class<?> injectorClass = loader.loadClass(injectorClassName);
                Method persist = injectorClass.getDeclaredMethod("persist", Class.class);
                persist.setAccessible(true);
                assertEquals(expectedBackup.toFile(), persist.invoke(null, originalTargetClass));
            }

            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                Class<?> persistedTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = persistedTargetClass.newInstance();
                persistedTargetClass.getMethod("doFilter").invoke(target);
                assertFalse(persistedTargetClass.getField("invoked").getBoolean(null));
            }
        } finally {
            Files.deleteIfExists(expectedBackup);
        }
    }

    @Test
    void persistArgumentIsOptIn() {
        assertFalse(TomcatFilterChainAgentInjector.isPersistent(null));
        assertFalse(TomcatFilterChainAgentInjector.isPersistent("persist=false"));
        assertFalse(TomcatFilterChainAgentInjector.isPersistent("persist=truex"));
        assertTrue(TomcatFilterChainAgentInjector.isPersistent("persist=true"));
        assertTrue(TomcatContextValveAgentInjector.isPersistent("other=value, persist=true"));
    }

    private void assertPersistence(String targetInternalName, String targetMethodName,
                                   PersistOperation persistOperation) throws Exception {
        String shellClassName = "test." + targetInternalName.substring(targetInternalName.lastIndexOf('/') + 1) + "Shell";
        byte[] originalTargetBytes = targetClass(targetInternalName, targetMethodName);
        byte[] shellClassBytes = shellClass(shellClassName.replace('.', '/'));
        String jarName = "tomcat-persistence-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        Path expectedBackup = Paths.get("/tmp").resolve(jarName + ".bak");
        try {
            writeJar(originalJar, targetInternalName + ".class", originalTargetBytes);
            byte[] originalJarBytes = Files.readAllBytes(originalJar);
            Class<?> originalTargetClass;
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                originalTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = originalTargetClass.newInstance();
                originalTargetClass.getMethod(targetMethodName).invoke(target);
                assertTrue(originalTargetClass.getField("invoked").getBoolean(null));
                assertEquals(expectedBackup.toFile(), persistOperation.persist(originalTargetClass, shellClassName, shellClassBytes));
            }

            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
            byte[] persistedJarBytes = Files.readAllBytes(originalJar);
            assertFalse(Arrays.equals(originalJarBytes, persistedJarBytes));
            try (JarFile persistedJar = new JarFile(originalJar.toFile())) {
                assertNotNull(persistedJar.getJarEntry(targetInternalName + ".class"));
                assertArrayEquals(shellClassBytes, readEntry(persistedJar, shellClassName.replace('.', '/') + ".class"));
                assertArrayEquals("keep".getBytes("UTF-8"), readEntry(persistedJar, "application.txt"));
            }

            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{originalJar.toUri().toURL()}, null)) {
                Class<?> persistedTargetClass = loader.loadClass(targetInternalName.replace('/', '.'));
                Object target = persistedTargetClass.newInstance();
                persistedTargetClass.getMethod(targetMethodName).invoke(target);
                assertFalse(persistedTargetClass.getField("invoked").getBoolean(null),
                        "The persisted hook should return before the original method body");
            }

            assertThrows(IllegalStateException.class,
                    () -> persistOperation.persist(originalTargetClass, shellClassName, shellClassBytes));
            assertArrayEquals(persistedJarBytes, Files.readAllBytes(originalJar));
            assertArrayEquals(originalJarBytes, Files.readAllBytes(expectedBackup));
        } finally {
            Files.deleteIfExists(expectedBackup);
        }
    }

    private static void writeGeneratedAgent(Path agentJar, String injectorClassName,
                                            String shellClassName, byte[] shellClassBytes) throws IOException {
        InjectorConfig config = InjectorConfig.builder()
                .shellClassBytes(shellClassBytes)
                .shellClassName(shellClassName)
                .injectorClassName(injectorClassName)
                .injectorTemplateClassName(TomcatFilterChainAgentInjector.class.getName())
                .injectorTemplateClassLoader(TomcatFilterChainAgentInjector.class.getClassLoader())
                .build();
        InjectorGenerator generator = new InjectorGenerator(
                ShellConfig.builder().shellType(ShellType.AGENT_FILTER_CHAIN).build(), config);
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

    private interface PersistOperation {
        File persist(Class<?> targetClass, String shellClassName, byte[] shellClassBytes) throws Exception;
    }
}
