package com.reajason.javaweb.asm;

import com.reajason.javaweb.asm.fixtures.TriggerTarget;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.load;
import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.messageOf;
import static com.reajason.javaweb.asm.fixtures.ClassBytesTestSupport.read;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClassInitializerTest {

    @BeforeEach
    void clearProperty() {
        System.clearProperty(TriggerTarget.CLINIT_PROPERTY);
    }

    @Test
    void addsTypeInitializerWhenMissing() throws Exception {
        byte[] result = ClassInitializer.ensurePresent(sampleClassWithoutClinit());

        assertTrue(hasTypeInitializer(result));

        load("test.NoClinit", result);
    }

    @Test
    void keepsExistingTypeInitializer() throws Exception {
        byte[] result = ClassInitializer.ensurePresent(read(TriggerTarget.class));

        load(TriggerTarget.class.getName(), result);

        assertEquals("yes", System.getProperty(TriggerTarget.CLINIT_PROPERTY));
    }

    @Test
    void leavesClassWithTypeInitializerUntouched() throws Exception {
        byte[] original = read(TriggerTarget.class);

        assertArrayEquals(original, ClassInitializer.ensurePresent(original));
    }

    @Test
    void rejectsModuleInfo() {
        assertTrue(messageOf(() -> ClassInitializer.ensurePresent(moduleInfo()))
                .contains("module-info"));
    }

    private static boolean hasTypeInitializer(byte[] classBytes) {
        final boolean[] found = {false};
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                found[0] |= "<clinit>".equals(name) && "()V".equals(descriptor);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return found[0];
    }

    private static byte[] sampleClassWithoutClinit() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/NoClinit", null, "java/lang/Object", null);
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] moduleInfo() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
        writer.visitModule("test.module", 0, null).visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
