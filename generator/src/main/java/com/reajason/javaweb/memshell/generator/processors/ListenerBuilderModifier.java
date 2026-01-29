package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.implementation.StubMethod;
import net.bytebuddy.matcher.ElementMatchers;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class ListenerBuilderModifier implements Processor<DynamicType.Builder<?>> {

    @Override
    public DynamicType.Builder<?> process(DynamicType.Builder<?> builder, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        String shellType = shellConfig.getShellType();
        if (ShellType.LISTENER.equals(shellType) || ShellType.JAKARTA_LISTENER.equals(shellType)) {
            AbstractServer server = ServerFactory.getServer(shellConfig.getServer());
            String shellClassName = shellToolConfig.getShellClassName();
            builder = modifier(builder,
                    server.getListenerInterceptor(),
                    shellToolConfig.getShellTypeDescription(),
                    shellClassName);
        }
        return builder;
    }

    public static DynamicType.Builder<?> modifier(DynamicType.Builder<?> builder, Class<?> implInterceptor,
                                                  TypeDescription typeDefinition, String newClassName) {
        MethodList<MethodDescription.InDefinedShape> methods = typeDefinition.getDeclaredMethods();

        if (methods.filter(named("getResponseFromRequest").and(takesArguments(1))).isEmpty()) {
            throw new GenerationException("please add [getResponseFromRequest(Object request)] method," +
                    " the method body will be auto adapted for multi server");
        } else {
            builder = builder
                    .visit(MethodCallReplaceVisitorWrapper.newInstance(
                            "getResponseFromRequest", newClassName, ShellCommonUtil.class.getName()))
                    .visit(Advice.to(implInterceptor).on(named("getResponseFromRequest")));
        }

        if (methods.filter(named("getFieldValue").and(takesArguments(Object.class, String.class))).isEmpty()) {
            builder = builder.defineMethod("getFieldValue", Object.class, Visibility.PUBLIC, Ownership.STATIC)
                    .withParameters(Object.class, String.class)
                    .throwing(Exception.class)
                    .intercept(StubMethod.INSTANCE)
                    .visit(Advice.to(ShellCommonUtil.GetFieldValueInterceptor.class).on(named("getFieldValue")));
        }
        return builder;
    }
}
