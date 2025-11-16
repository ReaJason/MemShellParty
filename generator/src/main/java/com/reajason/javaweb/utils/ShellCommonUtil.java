package com.reajason.javaweb.utils;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Field;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ShellCommonUtil {

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        return "";
    }

    public static class GetFieldValueInterceptor {
        @Advice.OnMethodExit
        @SuppressWarnings("all")
        public static void exit(@Advice.Argument(value = 0) Object obj,
                                @Advice.Argument(value = 1) String name,
                                @Advice.Return(readOnly = false) Object returnValue
        ) throws Exception {
            Class<?> clazz = obj.getClass();
            while (clazz != Object.class) {
                try {
                    Field field = clazz.getDeclaredField(name);
                    field.setAccessible(true);
                    returnValue = field.get(obj);
                    return;
                } catch (NoSuchFieldException var5) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (returnValue == null) {
                throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
            }
        }
    }


    @SuppressWarnings("all")
    public static String base64DecodeToString(String bs) throws Exception {
        return "";
    }

    public static class Base64DecodeToStringInterceptor {

        @Advice.OnMethodExit
        @SuppressWarnings("all")
        public static void exit(@Advice.Argument(value = 0, readOnly = false) String bs, @Advice.Return(readOnly = false) String returnValue) throws Exception {
            if (bs != null) {
                try {
                    Object decoder = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
                    returnValue = new String((byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs));
                } catch (Exception var6) {
                    Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
                    returnValue = new String((byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs));
                }
            }
        }
    }

    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
        return null;
    }
}
