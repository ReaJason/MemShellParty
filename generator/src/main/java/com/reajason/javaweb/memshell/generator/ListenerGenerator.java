package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;

import java.util.Collections;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ListenerGenerator {

    public static DynamicType.Builder<?> build(DynamicType.Builder<?> builder, Class<?> implInterceptor, Class<?> targetClass, String newClassName) {
        builder = builder.visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(named("getResponseFromRequest"),
                                new MethodCallReplaceVisitorWrapper(
                                        newClassName,
                                        Collections.singleton(ShellCommonUtil.class.getName()))
                        )
                )
                .visit(Advice.to(implInterceptor).on(named("getResponseFromRequest")));

        boolean methodNotFound = TypeDescription.ForLoadedType.of(targetClass)
                .getDeclaredMethods()
                .filter(named("getFieldValue")
                        .and(takesArguments(Object.class, String.class)))
                .isEmpty();

        if (methodNotFound) {
            builder = builder.defineMethod("getFieldValue", Object.class, Visibility.PUBLIC, Ownership.STATIC)
                    .withParameters(Object.class, String.class)
                    .throwing(Exception.class)
                    .intercept(FixedValue.nullValue())
                    .visit(Advice.to(ShellCommonUtil.GetFieldValueInterceptor.class).on(named("getFieldValue")));
        }
        return builder;
    }
}
