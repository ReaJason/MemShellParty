package com.reajason.javaweb.agent;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentInjectorSupportTest {
    private static final String TARGET_INTERNAL = "test/agent/HookTarget";
    private static final String TARGET_NAME = "test.agent.HookTarget";
    private static final String SHELL_NAME = "test.agent.HookShell";
    private static final String SHELL_INTERNAL = "test/agent/HookShell";

    @Test
    void voidHookTriggersShellAndSkipsOriginalBody() throws Exception {
        HookTargetLoader loader = new HookTargetLoader();
        Class<?> targetClass = transformAndDefine(loader, AgentInjectorSupport.Config.of(TARGET_INTERNAL, "doFilter"),
                targetClass("doFilter", "(Ljava/lang/Object;)V"));

        targetClass.getMethod("doFilter", Object.class).invoke(targetClass.newInstance(), "request");

        assertFalse((Boolean) targetClass.getField("invoked").get(null));
        assertArrayEquals(new Object[]{"request"}, shellArguments(loader));
    }

    @Test
    void intHookReturningValveEndsPipeline() throws Exception {
        HookTargetLoader loader = new HookTargetLoader();
        Class<?> targetClass = transformAndDefine(loader,
                AgentInjectorSupport.Config.of(TARGET_INTERNAL, "invoke").intHookResult(),
                targetClass("invoke", "()I"));

        Object result = targetClass.getMethod("invoke").invoke(targetClass.newInstance());

        assertEquals(2, result);
        assertFalse((Boolean) targetClass.getField("invoked").get(null));
        assertArrayEquals(new Object[0], shellArguments(loader));
    }

    @Test
    void intHookResultStillReturnsVoidForVoidMethods() throws Exception {
        HookTargetLoader loader = new HookTargetLoader();
        Class<?> targetClass = transformAndDefine(loader,
                AgentInjectorSupport.Config.of(TARGET_INTERNAL, "invoke").intHookResult(),
                targetClass("invoke", "(Ljava/lang/Object;)V"));

        targetClass.getMethod("invoke", Object.class).invoke(targetClass.newInstance(), "request");

        assertFalse((Boolean) targetClass.getField("invoked").get(null));
        assertArrayEquals(new Object[]{"request"}, shellArguments(loader));
    }

    @Test
    void primitiveArgumentsAreBoxedForShellEquals() throws Exception {
        HookTargetLoader loader = new HookTargetLoader();
        Class<?> targetClass = transformAndDefine(loader,
                AgentInjectorSupport.Config.of(TARGET_INTERNAL, "handle"),
                targetClass("handle", "(JLjava/lang/String;D)V"));

        Method handle = targetClass.getMethod("handle", long.class, String.class, double.class);
        handle.invoke(targetClass.newInstance(), 42L, "value", 2.5D);

        assertFalse((Boolean) targetClass.getField("invoked").get(null));
        assertArrayEquals(new Object[]{42L, "value", 2.5D}, shellArguments(loader));
    }

    @Test
    void defaultDefineStrategyReusesShellVisibleFromParentLoader() throws Exception {
        HookTargetLoader parent = new HookTargetLoader();
        parent.define(SHELL_NAME, shellClass());
        HookTargetLoader loader = new HookTargetLoader(parent);

        transformAndDefine(loader, AgentInjectorSupport.Config.of(TARGET_INTERNAL, "doFilter"),
                targetClass("doFilter", "(Ljava/lang/Object;)V"));

        assertFalse(loader.isDefinedHere(SHELL_NAME), "the visible shell must be reused");
        assertTrue(parent.isDefinedHere(SHELL_NAME));
    }

    @Test
    void defineIntoLoaderDefinesShellInTargetLoader() throws Exception {
        HookTargetLoader parent = new HookTargetLoader();
        parent.define(SHELL_NAME, shellClass());
        HookTargetLoader loader = new HookTargetLoader(parent);

        transformAndDefine(loader,
                AgentInjectorSupport.Config.of(TARGET_INTERNAL, "doFilter").defineIntoLoader(),
                targetClass("doFilter", "(Ljava/lang/Object;)V"));

        assertTrue(loader.isDefinedHere(SHELL_NAME), "OSGi-style loaders need their own shell copy");
    }

    @Test
    void unmatchedClassIsReturnedUnchanged() throws Exception {
        byte[] bytes = targetClass("doFilter", "(Ljava/lang/Object;)V");
        ClassFileTransformer transformer = AgentInjectorSupport.create(
                AgentInjectorSupport.Config.of("other/Missing", "doFilter"), SHELL_NAME, shellBase64());

        assertSame(bytes, transformer.transform(getClass().getClassLoader(), TARGET_INTERNAL,
                null, null, bytes));
    }

    @Test
    void malformedConfigIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> AgentInjectorSupport.Config.of("only/ClassName"));
    }

    private static Class<?> transformAndDefine(HookTargetLoader loader,
                                               AgentInjectorSupport.Config config,
                                               byte[] targetClassBytes) throws Exception {
        ClassFileTransformer transformer = AgentInjectorSupport.create(config, SHELL_NAME, shellBase64());
        byte[] transformed = transformer.transform(loader, TARGET_INTERNAL, null, null, targetClassBytes);
        return loader.define(TARGET_NAME, transformed);
    }

    private static Object[] shellArguments(ClassLoader loader) throws Exception {
        Class<?> shell = loader.loadClass(SHELL_NAME);
        assertTrue((Boolean) shell.getField("triggered").get(null), "the shell hook must run");
        return (Object[]) shell.getField("arguments").get(null);
    }

    private static String shellBase64() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            GZIPOutputStream gzip = new GZIPOutputStream(output);
            try {
                gzip.write(shellClass());
            } finally {
                gzip.close();
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return Base64.getEncoder().encodeToString(output.toByteArray());
    }

    private static byte[] targetClass(String methodName, String descriptor) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, TARGET_INTERNAL, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "invoked", "Z", null, null).visitEnd();
        defaultConstructor(writer);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, methodName, descriptor, null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ICONST_1);
        method.visitFieldInsn(Opcodes.PUTSTATIC, TARGET_INTERNAL, "invoked", "Z");
        if (descriptor.endsWith(")I")) {
            method.visitInsn(Opcodes.ICONST_0);
            method.visitInsn(Opcodes.IRETURN);
        } else {
            method.visitInsn(Opcodes.RETURN);
        }
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] shellClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, SHELL_INTERNAL, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "triggered", "Z", null, null).visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "arguments", "[Ljava/lang/Object;", null, null).visitEnd();
        defaultConstructor(writer);
        MethodVisitor equals = writer.visitMethod(Opcodes.ACC_PUBLIC, "equals", "(Ljava/lang/Object;)Z", null, null);
        equals.visitCode();
        equals.visitInsn(Opcodes.ICONST_1);
        equals.visitFieldInsn(Opcodes.PUTSTATIC, SHELL_INTERNAL, "triggered", "Z");
        equals.visitVarInsn(Opcodes.ALOAD, 1);
        equals.visitTypeInsn(Opcodes.CHECKCAST, "[Ljava/lang/Object;");
        equals.visitFieldInsn(Opcodes.PUTSTATIC, SHELL_INTERNAL, "arguments", "[Ljava/lang/Object;");
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

    private static final class HookTargetLoader extends ClassLoader {
        private HookTargetLoader() {
            this(AgentInjectorSupportTest.class.getClassLoader());
        }

        private HookTargetLoader(ClassLoader parent) {
            super(parent);
        }

        private Class<?> define(String className, byte[] classBytes) {
            Class<?> loaded = findLoadedClass(className);
            return loaded != null ? loaded : defineClass(className, classBytes, 0, classBytes.length);
        }

        private boolean isDefinedHere(String className) {
            return findLoadedClass(className) != null;
        }
    }
}
