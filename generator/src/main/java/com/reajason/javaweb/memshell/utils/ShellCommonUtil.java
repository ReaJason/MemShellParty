package com.reajason.javaweb.memshell.utils;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Field;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
public class ShellCommonUtil {

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }

    public static class GetFieldValueInterceptor {
        @Advice.OnMethodExit
        @SuppressWarnings("all")
        public static void exit(@Advice.Argument(value = 0) Object obj,
                                @Advice.Argument(value = 1) String name,
                                @Advice.Return(readOnly = false) Object returnValue
        ) throws Exception {
            Field field = null;
            Class<?> clazz = obj.getClass();
            while (clazz != Object.class) {
                try {
                    field = clazz.getDeclaredField(name);
                    break;
                } catch (NoSuchFieldException var5) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (field == null) {
                throw new NoSuchFieldException(name);
            } else {
                field.setAccessible(true);
                returnValue = field.get(obj);
                return;
            }
        }
    }


    @SuppressWarnings("all")
    public static String base64DecodeToString(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value == null ? "" : new String(value);
    }

    public static class Base64DecodeToStringInterceptor {

        @Advice.OnMethodExit
        @SuppressWarnings("all")
        public static void exit(@Advice.Argument(value = 0, readOnly = false) String bs, @Advice.Return(readOnly = false) String returnValue) {
            byte[] value = null;
            Class<?> base64;
            try {
                base64 = Class.forName("java.util.Base64");
                Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
            } catch (Exception var6) {
                try {
                    base64 = Class.forName("sun.misc.BASE64Decoder");
                    Object decoder = base64.newInstance();
                    value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
                } catch (Exception ignored) {
                }
            }
            returnValue = value == null ? "" : new String(value);
        }
    }
}
