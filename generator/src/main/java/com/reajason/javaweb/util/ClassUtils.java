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
        return ClassDefiner.defineClass(bytes);
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
}