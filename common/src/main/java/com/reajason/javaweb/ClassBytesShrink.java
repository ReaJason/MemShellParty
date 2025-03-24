package com.reajason.javaweb;

import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2025/2/25
 */
public class ClassBytesShrink {

    public static byte[] shrink(byte[] bytes, boolean full) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public void visitSource(String source, String debug) {

            }
        };
        cr.accept(cv, full ? ClassReader.SKIP_DEBUG : 0);
        return cw.toByteArray();
    }
}
