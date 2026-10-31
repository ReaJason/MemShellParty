package com.reajason.javaweb.asm;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Opcodes;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 包名前缀替换只应命中完整包名，不能把 com.example 当成 com.example2 的前缀。
 */
class ClassRenameUtilsTest {

    @Test
    void relocatesPackageSubtree() {
        byte[] sample = sampleClassReferencing("com/example/http/Request");

        byte[] result = ClassRenameUtils.relocateClass(sample, "com.example", "example.renamed");

        assertEquals("Lexample/renamed/http/Request;", firstFieldDescriptor(result));
    }

    @Test
    void leavesLongerPackageNamesUntouched() {
        byte[] sample = sampleClassReferencing("com/example2/http/Request");

        byte[] result = ClassRenameUtils.relocateClass(sample, "com.example", "example.renamed");

        assertEquals("Lcom/example2/http/Request;", firstFieldDescriptor(result));
    }

    private static byte[] sampleClassReferencing(String fieldType) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "test/Sample", null, "java/lang/Object", null);
        FieldVisitor field = writer.visitField(Opcodes.ACC_PUBLIC, "request", "L" + fieldType + ";", null, null);
        field.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static String firstFieldDescriptor(byte[] classBytes) {
        final String[] descriptor = new String[1];
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public FieldVisitor visitField(int access, String name, String fieldDescriptor,
                                           String signature, Object value) {
                descriptor[0] = fieldDescriptor;
                return null;
            }
        }, 0);
        return descriptor[0];
    }
}
