package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.matcher.ElementMatchers;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ListenerGenerator {

    public static DynamicType.Builder<?> build(DynamicType.Builder<?> builder, Class<?> implInterceptor,
                                               TypeDescription typeDefinition, String newClassName) {
        MethodList<MethodDescription.InDefinedShape> methods = typeDefinition.getDeclaredMethods();

        if (methods.filter(ElementMatchers.named("getResponseFromRequest")
                        .and(ElementMatchers.takesArguments(Object.class))
                        .and(ElementMatchers.returns(Object.class)))
                .isEmpty()) {
            throw new GenerationException("[public Object getResponseFromRequest(Object request)] method not found" +
                    " make sure arg and return type is Object.class");
        } else {
            builder = builder
                    .visit(MethodCallReplaceVisitorWrapper.newInstance(
                            "getResponseFromRequest", newClassName, ShellCommonUtil.class.getName()))
                    .visit(Advice.to(implInterceptor).on(named("getResponseFromRequest")));
        }

        if (methods.filter(named("getFieldValue")
                        .and(takesArguments(Object.class, String.class)))
                .isEmpty()) {
            builder = builder.defineMethod("getFieldValue", Object.class, Visibility.PUBLIC, Ownership.STATIC)
                    .withParameters(Object.class, String.class)
                    .throwing(Exception.class)
                    .intercept(FixedValue.nullValue())
                    .visit(Advice.to(ShellCommonUtil.GetFieldValueInterceptor.class).on(named("getFieldValue")));
        }
        return builder;
    }
}
