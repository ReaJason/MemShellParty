package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.shelltool.TestFilterChain;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

import java.util.Objects;

/**
 * @author ReaJason
 * @since 2025/5/15
 */
public class CommandNormalASMTest {
    @Test
    @SneakyThrows
    void test() {
        byte[] bytes = IOUtils.toByteArray(Objects.requireNonNull(TestFilterChain.class.getClassLoader().getResource(TestFilterChain.class.getName().replace('.', '/') + ".class")));
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("doFilter".equals(name)) {
                    return new CommandFilterChainAsmMethodVisitor(mv, access, name, descriptor);
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        byte[] bytes2 = ClassRenameUtils.renameClass(cw.toByteArray(), TestFilterChain.class.getName() + "Asm");
//        IOUtils.write(bytes2, new FileOutputStream("test.class"));
    }

    static class Hello {
        @Override
        public boolean equals(Object obj) {
            System.out.println("hello world");
            return true;
        }
    }

    static class CommandFilterChainAsmMethodVisitor extends AdviceAdapter {
        private static final Method CUSTOM_EQUALS_CONSTRUCTOR = Method.getMethod("void <init> ()");
        private static final Method CUSTOM_EQUALS_METHOD = Method.getMethod("boolean equals (java.lang.Object)");
        private final Type customEqualsType;

        protected CommandFilterChainAsmMethodVisitor(MethodVisitor mv, int access, String name, String descriptor) {
            super(Opcodes.ASM9, mv, access, name, descriptor);
            customEqualsType = Type.getObjectType("com.reajason.javaweb.memshell.shelltool.command.CommandNormalASMTest.Hello".replace('.', '/'));
        }

        @Override
        protected void onMethodEnter() {
            loadArgArray();
            newInstance(customEqualsType);
            dup();
            invokeConstructor(customEqualsType, CUSTOM_EQUALS_CONSTRUCTOR);
            swap();
            invokeVirtual(customEqualsType, CUSTOM_EQUALS_METHOD);
            Label skipReturnLabel = new Label();
            mv.visitJumpInsn(IFEQ, skipReturnLabel);
            mv.visitInsn(RETURN);
            mark(skipReturnLabel);
        }
    }
}
