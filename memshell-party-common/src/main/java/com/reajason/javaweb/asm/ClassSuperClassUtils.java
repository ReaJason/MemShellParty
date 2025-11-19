package com.reajason.javaweb.asm;

import org.objectweb.asm.*;

public class ClassSuperClassUtils {

    public static byte[] addSuperClass(byte[] bytes, String superClassName) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(cr, 0);
        ClassVisitor cv = new AddSuperClassAdapter(cw, superClassName.replace('.', '/'));
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    static class AddSuperClassAdapter extends ClassVisitor {
        private final String newSuperName;

        public AddSuperClassAdapter(ClassVisitor cv, String newSuperName) {
            super(Opcodes.ASM9, cv);
            this.newSuperName = newSuperName;
        }

        @Override
        public void visit(int version, int access, String name,
                          String signature, String superName, String[] interfaces) {
            if (!"java/lang/Object".equals(superName)) {
                throw new IllegalStateException(String.format(
                        "Cannot add superclass to class '%s': it already extends '%s'.", name, superName
                ));
            }
            super.visit(version, access, name, signature, newSuperName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if ("<init>".equals(name)) {
                return new ChangeConstructorAdapter(mv, newSuperName);
            }
            return mv;
        }
    }

    static class ChangeConstructorAdapter extends MethodVisitor {
        private final String newSuperName;

        public ChangeConstructorAdapter(MethodVisitor mv, String newSuperName) {
            super(Opcodes.ASM9, mv);
            this.newSuperName = newSuperName;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String descriptor, boolean isInterface) {
            if (opcode == Opcodes.INVOKESPECIAL &&
                    "java/lang/Object".equals(owner) &&
                    "<init>".equals(name)) {
                super.visitMethodInsn(opcode, newSuperName, name, descriptor, isInterface);
            } else {
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        }
    }
}