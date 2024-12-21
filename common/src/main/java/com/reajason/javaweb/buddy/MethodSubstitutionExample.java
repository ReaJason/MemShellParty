package com.reajason.javaweb.buddy;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;

import java.nio.file.Files;
import java.nio.file.Paths;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class MethodSubstitutionExample {


    public static class MethodReplacementMethodVisitor extends MethodVisitor {
        private final String targetClassName;

        public MethodReplacementMethodVisitor(MethodVisitor mv, String targetClassName) {
            super(Opcodes.ASM9, mv);
            this.targetClassName = targetClassName;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            if (opcode == Opcodes.INVOKESTATIC
                    && owner.endsWith("ExternalClass")
                    && name.equals("replacementMethod")) {
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        targetClassName.replace(".", "/"),
                        name,
                        descriptor,
                        false);
            } else {
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        }
    }

    public static class ExternalClass {
        public static String externalMethod(String input) {
            return "External: " + input;
        }

        public static String replacementMethod(String input) {
            return "Replaced: " + input;
        }
    }

    public static class TargetClass {
        public String targetMethod(String input) {
            System.out.println("targetMethod");
            return ExternalClass.replacementMethod(input);
        }

        public static String replacementMethod(String input) {
            return "Replaced: " + input;
        }
    }

    public static void main(String[] args) throws Exception {
        String oldClassName = TargetClass.class.getName();
        String newClassName = oldClassName + "Redefinition";

        DynamicType.Unloaded<TargetClass> dynamicType = new ByteBuddy()
                .redefine(TargetClass.class)
                .name(newClassName)
                .visit(new AsmVisitorWrapper.ForDeclaredMethods().method(named("targetMethod"), (typeDescription, methodDescription, methodVisitor, context, typePool, i, i1) -> new MethodReplacementMethodVisitor(methodVisitor, newClassName)))
                .make();

        Files.write(Paths.get("xixi.class"), dynamicType.getBytes());
        Class<?> redefinedClass = dynamicType.load(MethodSubstitutionExample.class.getClassLoader())
                .getLoaded();
    }
}
