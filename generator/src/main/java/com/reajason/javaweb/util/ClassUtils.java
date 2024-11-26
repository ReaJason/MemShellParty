package com.reajason.javaweb.util;

import lombok.SneakyThrows;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class ClassUtils {

    @SneakyThrows
    public static Class<?> defineClass(byte[] bytes) {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        return (Class<?>) defineClass.invoke(ClassUtils.class.getClassLoader(), bytes, 0, bytes.length);
    }

    @SneakyThrows
    public static Object newInstance(byte[] bytes) {
        Class<?> clazz = defineClass(bytes);
        return clazz.newInstance();
    }

    @SneakyThrows
    public static Object getFieldValue(Object object, String fieldName) {
        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(object);
    }

    @SneakyThrows
    public static Object invokeMethod(Object object, String methodName, Class<?>[] parameterTypes, Object[] parameters) {
        Method method = object.getClass().getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return method.invoke(object, parameters);
    }

    public static void byPassJdkModule() {
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
            getAndSetObjectM.invoke(unsafe, ClassUtils.class, offset, module);
        } catch (Exception ignored) {
        }
    }
}