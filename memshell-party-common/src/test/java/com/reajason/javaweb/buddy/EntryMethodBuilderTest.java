package com.reajason.javaweb.buddy;

import com.reajason.javaweb.asm.fixtures.TriggerTarget;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.load;
import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.messageOf;
import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.read;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 入口方法生成的行为验证：添加后的方法能通过反射调用，并执行构造 + toString。
 */
class EntryMethodBuilderTest {

    private static final String FIXTURE = TriggerTarget.class.getName();

    private byte[] fixtureBytes;

    @BeforeEach
    void setUp() throws Exception {
        fixtureBytes = read(TriggerTarget.class);
        System.clearProperty(TriggerTarget.PROPERTY);
        System.clearProperty(TriggerTarget.CLINIT_PROPERTY);
    }

    @Test
    void addEntryReturnsToStringResult() throws Exception {
        byte[] result = EntryMethodBuilder.add(fixtureBytes,
                "public static String exec(final String value)");

        Class<?> clazz = load(FIXTURE, result);
        Method entry = clazz.getMethod("exec", String.class);

        assertTrue(Modifier.isStatic(entry.getModifiers()));
        assertEquals(String.class, entry.getReturnType());
        assertEquals("TriggerTarget", entry.invoke(null, "ignored"));
        assertEquals("toString", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addEntryHonorsPrivateInstanceMethodSignature() throws Exception {
        byte[] result = EntryMethodBuilder.add(fixtureBytes, "private void test()");

        Class<?> clazz = load(FIXTURE, result);
        Method entry = clazz.getDeclaredMethod("test");

        assertTrue(Modifier.isPrivate(entry.getModifiers()));
        assertFalse(Modifier.isStatic(entry.getModifiers()));
        entry.setAccessible(true);
        entry.invoke(clazz.getDeclaredConstructor().newInstance());
        assertEquals("toString", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addEntryHonorsInstanceMethodSignature() throws Exception {
        byte[] result = EntryMethodBuilder.add(fixtureBytes, "public void hello()");

        Class<?> clazz = load(FIXTURE, result);
        Method entry = clazz.getMethod("hello");

        assertFalse(Modifier.isStatic(entry.getModifiers()));
        entry.invoke(clazz.getDeclaredConstructor().newInstance());
        assertEquals("toString", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addEntryDefaultsToVoidForBcelMainSignature() throws Exception {
        byte[] result = EntryMethodBuilder.add(fixtureBytes, "_main(String[] args)");

        Class<?> clazz = load(FIXTURE, result);
        Method entry = clazz.getMethod("_main", String[].class);

        assertEquals(void.class, entry.getReturnType());
        assertTrue(Modifier.isStatic(entry.getModifiers()));
        assertEquals(null, entry.invoke(null, (Object) new String[0]));
        assertEquals("toString", System.getProperty(TriggerTarget.PROPERTY));
    }

    @Test
    void addEntryDoesNotRequireParameterTypeOnGenerationClasspath() {
        byte[] result = EntryMethodBuilder.add(fixtureBytes,
                "public static String exec(example.missing.Request request)");
        final String[] descriptor = new String[1];
        new ClassReader(result).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String methodDescriptor,
                                             String signature, String[] exceptions) {
                if ("exec".equals(name)) {
                    descriptor[0] = methodDescriptor;
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);

        assertEquals("(Lexample/missing/Request;)Ljava/lang/String;", descriptor[0]);
    }

    @Test
    void rejectsDuplicateEntryWithSameParameters() {
        byte[] once = EntryMethodBuilder.add(fixtureBytes, "String exec(String value)");

        assertTrue(messageOf(() -> EntryMethodBuilder.add(once, "exec(String other)"))
                .contains("已存在相同参数的方法"));
    }

    @Test
    void rejectsEntryNamedLikeCurrentClass() {
        byte[] bytes = sampleClassWithNoArgConstructor("test/FixedAssertingListener");

        assertTrue(messageOf(() -> EntryMethodBuilder.add(bytes,
                "public void FixedAssertingListener()")).contains("不能与当前类名相同"));
    }

    @Test
    void rejectsEntryWithoutNoArgConstructor() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/StringOnly", null, "java/lang/Object", null);
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>",
                "(Ljava/lang/String;)V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 2);
        constructor.visitEnd();
        writer.visitEnd();

        assertTrue(messageOf(() -> EntryMethodBuilder.add(writer.toByteArray(), "exec()"))
                .contains("没有无参构造方法"));
    }

    private static byte[] sampleClassWithNoArgConstructor(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
