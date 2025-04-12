package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.MethodCallReplaceVisitorWrapper;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;

import java.util.Collections;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ListenerGenerator {

    public static Class<?> generateListenerShellClass(Class<?> implInterceptor, Class<?> targetClass) {
        String newClassName = targetClass.getName() + CommonUtil.getRandomString(5);

        try (DynamicType.Unloaded<?> unloaded = new ByteBuddy()
                .redefine(targetClass)
                .name(newClassName)
                .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(named("getResponseFromRequest"),
                                new MethodCallReplaceVisitorWrapper(
                                        newClassName,
                                        Collections.singleton(ShellCommonUtil.class.getName()))
                        )
                )
                .visit(Advice.to(implInterceptor).on(named("getResponseFromRequest")))
                .make()) {
            return unloaded
                    .load(ListenerGenerator.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER_PERSISTENT)
                    .getLoaded();
        }
    }
}
