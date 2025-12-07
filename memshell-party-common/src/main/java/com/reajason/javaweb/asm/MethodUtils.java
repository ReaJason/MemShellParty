package com.reajason.javaweb.asm;

import org.objectweb.asm.*;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class MethodUtils {

    public static byte[] removeMethod(byte[] bytes, String methodName) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(0);
        RemoveMethodAdapter adapter = new RemoveMethodAdapter(cw, methodName);
        cr.accept(adapter, 0);
        return cw.toByteArray();
    }

    public static byte[] removeMethodByMethodDescriptor(byte[] bytes, String methodName, String methodDescriptor) {
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(0);
        RemoveMethodAdapter adapter = new RemoveMethodAdapter(cw, methodName, methodDescriptor);
        cr.accept(adapter, 0);
        return cw.toByteArray();
    }

    static class RemoveMethodAdapter extends ClassVisitor {
        private String methodName;
        private String methodDescriptor;

        public RemoveMethodAdapter(ClassVisitor cv, String methodName) {
            super(Opcodes.ASM9, cv);
            this.methodName = methodName;
        }

        public RemoveMethodAdapter(ClassVisitor cv, String methodName, String methodDescriptor) {
            super(Opcodes.ASM9, cv);
            this.methodName = methodName;
            this.methodDescriptor = methodDescriptor;
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor,
                String signature, String[] exceptions) {
            if (methodDescriptor != null) {
                if (methodDescriptor.equals(descriptor) && methodName.equals(name)) {
                    return null;
                }
            } else if (methodName.equals(name)) {
                return null;
            }
            return super.visitMethod(access, name, descriptor, signature, exceptions);
        }
    }

}
