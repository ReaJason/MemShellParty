package com.reajason.javaweb.asm;

import lombok.Getter;
import org.objectweb.asm.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Getter
public class ClassReferenceVisitor extends ClassVisitor {
    private final Set<String> referencedClasses = new HashSet<>();

    public ClassReferenceVisitor() {
        super(Opcodes.ASM9);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        if (superName != null) {
            referencedClasses.add(superName);
        }
        if (interfaces != null) {
            Collections.addAll(referencedClasses, interfaces);
        }
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
        addType(Type.getType(descriptor));
        return super.visitField(access, name, descriptor, signature, value);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        addType(Type.getMethodType(descriptor));
        if (exceptions != null) {
            Collections.addAll(referencedClasses, exceptions);
        }
        return new MethodReferenceVisitor(super.visitMethod(access, name, descriptor, signature, exceptions));
    }

    private void addType(Type type) {
        if (type.getSort() == Type.OBJECT) {
            referencedClasses.add(type.getInternalName());
        } else if (type.getSort() == Type.ARRAY) {
            addType(type.getElementType());
        } else if (type.getSort() == Type.METHOD) {
            addType(type.getReturnType());
            for (Type argType : type.getArgumentTypes()) {
                addType(argType);
            }
        }
    }

    class MethodReferenceVisitor extends MethodVisitor {
        public MethodReferenceVisitor(MethodVisitor methodVisitor) {
            super(Opcodes.ASM9, methodVisitor);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            referencedClasses.add(owner);
            addType(Type.getMethodType(descriptor));
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof Type) {
                addType((Type) value);
            }
            super.visitLdcInsn(value);
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            referencedClasses.add(type);
            super.visitTypeInsn(opcode, type);
        }
    }
}