package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Field;

import static net.bytebuddy.matcher.ElementMatchers.isTypeInitializer;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 */
public class ByPassJdkModuleInterceptor {
    @Advice.OnMethodExit
    public static void enter(@Advice.Origin Class<?> clazz, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) boolean returnValue) {
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            java.lang.reflect.Method getModuleM = Class.class.getMethod("getModule");
            Object module = getModuleM.invoke(Object.class, (Object[]) null);
            java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            java.lang.reflect.Field moduleF = Class.class.getDeclaredField("module");
            Long offset = (Long) objectFieldOffsetM.invoke(unsafe, moduleF);
            java.lang.reflect.Method getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, clazz, offset, module);
            returnValue = true;
        } catch (Exception ignored) {
        }
    }

    public static DynamicType.Builder<?> extend(DynamicType.Builder<?> builder) {
        return builder
                .defineField("isBypassModule", boolean.class, Visibility.PUBLIC, Ownership.STATIC)
                .invokable(isTypeInitializer())
                .intercept(MethodCall.invoke(named("byPassJdkModule")))
                .defineMethod("byPassJdkModule", Object.class, Visibility.PUBLIC, Ownership.STATIC)
                .intercept(FixedValue.value(false))
                .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(named("byPassJdkModule"),
                                Advice.to(ByPassJdkModuleInterceptor.class)));
    }
}