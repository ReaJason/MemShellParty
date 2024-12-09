package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.implementation.MethodCall;

import java.lang.reflect.Field;

import static net.bytebuddy.matcher.ElementMatchers.isTypeInitializer;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * JDK9 引入的 module 系统，只有主动声明 exports 的才能被外部访问。当前用于打破 module 的限制，使我们能像低版本一样任意反射获取方法
 *
 * @author ReaJason
 */
public class ByPassJavaModuleInterceptor {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> clazz) {
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            Long offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            java.lang.reflect.Method getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, clazz, offset, module);
        } catch (Exception ignored) {
        }
    }

    /**
     * Reference1: <a href="https://stackoverflow.com/questions/62664427/can-i-create-a-bytebuddy-instrumented-type-with-a-private-static-final-methodhan">stackoverflow</a>
     * Reference2: <a href="https://github.com/raphw/byte-buddy/issues/1153">issue</a>
     * <br>
     * 向类中添加 byPassJdkModule 方法，并在静态代码块中执行 byPassJdkModule 方法
     * 值得注意的一点，builder 是不可变类型，所以都是需要重新赋值，例如以下代码示例
     * # code that not work
     * builder = new Bytebuddy().redefine(class);
     * builder.visit(something);
     * builder.make();
     * <br>
     * # code that work
     * <br>
     * builder = new Bytebuddy().redefine(class);
     * builder = builder.visit(something);
     * builder.make();
     *
     * @param builder bytebuddy builder
     * @return new builder with bypass
     */
    public static DynamicType.Builder<?> extend(DynamicType.Builder<?> builder) {
        return builder
                .defineMethod("byPassJdkModule", void.class, Visibility.PUBLIC, Ownership.STATIC)
                .intercept(FixedValue.originType())
                .visit(new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(named("byPassJdkModule"),
                                Advice.to(ByPassJavaModuleInterceptor.class)))
                .invokable(isTypeInitializer())
                .intercept(MethodCall.invoke(named("byPassJdkModule")));
    }
}