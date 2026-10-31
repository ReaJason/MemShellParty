package com.reajason.javaweb.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class AgentPersistenceTest {
    private static final String TARGET_INTERNAL_NAME = "test/agent/AgentPersistenceTarget";
    private static final String TARGET_CLASS_NAME = TARGET_INTERNAL_NAME.replace('/', '.');
    private static final String SHELL_CLASS_NAME = "test.agent.PersistedShell";

    @TempDir
    Path tempDir;

    @Test
    void restoreArgumentIsOptIn() {
        assertFalse(AgentPersistence.isRestore(null));
        assertFalse(AgentPersistence.isRestore("persist=true"));
        assertFalse(AgentPersistence.isRestore("restore=false"));
        assertTrue(AgentPersistence.isRestore("restore=true"));
        assertTrue(AgentPersistence.isRestore("other=value, restore=TRUE"));
    }

    @Test
    void restoreRevertsJarAndLoadedClass() throws Exception {
        String jarName = "agent-restore-" + UUID.randomUUID() + ".jar";
        Path originalJar = tempDir.resolve(jarName);
        File backupJar = Paths.get("/tmp").resolve(jarName + ".bak").toFile();
        Files.deleteIfExists(backupJar.toPath());
        byte[] originalJarBytes = writeJar(originalJar);

        URLClassLoader loader = new URLClassLoader(new URL[]{originalJar.toUri().toURL()}, null);
        try {
            Class<?> targetClass = loader.loadClass(TARGET_CLASS_NAME);
            assertEquals(backupJar, AgentPersistence.persist(targetClass, SHELL_CLASS_NAME,
                    shellClass(), new IdentityTransformer()));
            assertTrue(backupJar.isFile());
            assertFalse(Arrays.equals(originalJarBytes, Files.readAllBytes(originalJar)),
                    "The persisted jar should contain the shell class");

            RecordingInstrumentation instrumentation = new RecordingInstrumentation();
            assertEquals(originalJar.toFile(),
                    AgentPersistence.restore(instrumentation.proxy(), targetClass));

            assertArrayEquals(originalJarBytes, Files.readAllBytes(originalJar));
            assertFalse(backupJar.exists(), "The restored backup should be removed");
            assertNotNull(instrumentation.redefined, "The loaded class should be redefined back");
            assertSame(targetClass, instrumentation.redefined.getDefinitionClass());
            assertArrayEquals(targetClass(), instrumentation.redefined.getDefinitionClassFile());

            assertEquals(backupJar, AgentPersistence.persist(targetClass, SHELL_CLASS_NAME,
                    shellClass(), new IdentityTransformer()),
                    "A restored jar should be persistable again");
            assertTrue(backupJar.isFile());
        } finally {
            loader.close();
            Files.deleteIfExists(backupJar.toPath());
        }
    }

    @Test
    void restoreRequiresBackup() throws Exception {
        Path originalJar = tempDir.resolve("agent-no-backup-" + UUID.randomUUID() + ".jar");
        writeJar(originalJar);
        URLClassLoader loader = new URLClassLoader(new URL[]{originalJar.toUri().toURL()}, null);
        try {
            Class<?> targetClass = loader.loadClass(TARGET_CLASS_NAME);
            RecordingInstrumentation instrumentation = new RecordingInstrumentation();
            IllegalStateException error = assertThrows(IllegalStateException.class,
                    () -> AgentPersistence.restore(instrumentation.proxy(), targetClass));
            assertTrue(error.getMessage().contains("No persistence backup"));
            assertNull(instrumentation.redefined);
        } finally {
            loader.close();
        }
    }

    private static byte[] writeJar(Path jarPath) throws Exception {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath))) {
            output.putNextEntry(new JarEntry(TARGET_INTERNAL_NAME + ".class"));
            output.write(targetClass());
            output.closeEntry();
            output.putNextEntry(new JarEntry("application.txt"));
            output.write("keep".getBytes("UTF-8"));
            output.closeEntry();
        }
        return Files.readAllBytes(jarPath);
    }

    private static byte[] targetClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, TARGET_INTERNAL_NAME,
                null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "invoked", "Z", null, null).visitEnd();
        defaultConstructor(writer);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_1);
        method.visitFieldInsn(Opcodes.PUTSTATIC, TARGET_INTERNAL_NAME, "invoked", "Z");
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] shellClass() {
        String internalName = SHELL_CLASS_NAME.replace('.', '/');
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null);
        defaultConstructor(writer);
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

    private static final class IdentityTransformer implements AgentPersistence.Transformer {
        @Override
        public byte[] transform(ClassLoader loader, byte[] classBytes) {
            return classBytes;
        }
    }

    private static final class RecordingInstrumentation implements InvocationHandler {
        private ClassDefinition redefined;

        private Instrumentation proxy() {
            return (Instrumentation) Proxy.newProxyInstance(AgentPersistenceTest.class.getClassLoader(),
                    new Class<?>[]{Instrumentation.class}, this);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if ("redefineClasses".equals(method.getName())) {
                redefined = ((ClassDefinition[]) args[0])[0];
                return null;
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == boolean.class) {
                return false;
            }
            if (returnType == int.class) {
                return 0;
            }
            if (returnType == long.class) {
                return 0L;
            }
            return null;
        }
    }
}
