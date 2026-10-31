package com.reajason.javaweb.asm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * 保证类有静态初始化块。Byte Buddy 的 Advice 只能改写已有方法，
 * 需要把模块绕过等逻辑挂到 {@code <clinit>} 时先调用本工具补一个空块。
 */
public final class ClassInitializer {

    private static final String CLINIT = "<clinit>";
    private static final String NO_ARG_DESCRIPTOR = "()V";

    private ClassInitializer() {
    }

    public static byte[] ensurePresent(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        if ((reader.getAccess() & Opcodes.ACC_MODULE) != 0) {
            throw new IllegalArgumentException("module-info 不能添加静态初始化代码");
        }
        if (hasTypeInitializer(reader)) {
            return classBytes;
        }
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visitEnd() {
                MethodVisitor clinit = super.visitMethod(Opcodes.ACC_STATIC, CLINIT,
                        NO_ARG_DESCRIPTOR, null, null);
                clinit.visitCode();
                clinit.visitInsn(Opcodes.RETURN);
                clinit.visitMaxs(0, 0);
                clinit.visitEnd();
                super.visitEnd();
            }
        }, 0);
        return writer.toByteArray();
    }

    private static boolean hasTypeInitializer(ClassReader reader) {
        final boolean[] found = {false};
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                found[0] |= CLINIT.equals(name) && NO_ARG_DESCRIPTOR.equals(descriptor);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return found[0];
    }
}
