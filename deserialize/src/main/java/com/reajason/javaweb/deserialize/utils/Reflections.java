package com.reajason.javaweb.deserialize.utils;

import com.reajason.javaweb.deserialize.payload.CommonsBeanutils19;

import java.lang.reflect.Field;

/**
 * @author ReaJason
 */
@SuppressWarnings("restriction")
public class Reflections {
    static {
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            Long offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            java.lang.reflect.Method getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, CommonsBeanutils19.class, offset, module);
        } catch (Exception ignored) {
        }
    }

    public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null) {
                field = getField(clazz.getSuperclass(), fieldName);
            }
        }
        return field;
    }

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }


    public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }
}
