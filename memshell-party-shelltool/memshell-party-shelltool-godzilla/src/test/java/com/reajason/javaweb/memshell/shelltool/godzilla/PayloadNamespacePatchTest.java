package com.reajason.javaweb.memshell.shelltool.godzilla;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Godzilla 4.01 的 WebSocket payload 硬编码引用 javax.websocket.Session，jakarta 容器上
 * checkcast 解析失败抛 NoClassDefFoundError（Error 穿透 payload 的 catch (Exception)）。
 * 模板在 defineClass 前把 payload 常量池中的 javax/websocket 改写为 jakarta/websocket。
 *
 * @author ReaJason
 */
class PayloadNamespacePatchTest {

    @Test
    void rewriteWebSocketRefs() throws Exception {
        byte[] origin = readClassBytes(GodzillaWebSocket.class);
        assertTrue(contains(origin, "javax/websocket"));
        byte[] patched = rewriteConstantPool(GodzillaRawWebSocket.class, origin);
        assertFalse(contains(patched, "javax/websocket"));
        assertTrue(contains(patched, "jakarta/websocket"));
        // 改写后的类文件结构仍然合法
        assertEquals(new ClassReader(origin).getClassName(), new ClassReader(patched).getClassName());
    }

    @Test
    void rewriteOnlyTouchesWebSocketRefs() throws Exception {
        byte[] origin = readClassBytes(GodzillaFilter.class);
        assertFalse(contains(origin, "javax/websocket"));
        assertTrue(contains(origin, "javax/servlet"));
        byte[] patched = rewriteConstantPool(GodzillaWebSocket.class, origin);
        // javax.servlet、javax.imageio 等无关命名空间保持原样
        assertArrayEquals(origin, patched);
    }

    @Test
    void rewriteKeepsUnrelatedClassBytes() throws Exception {
        byte[] origin = readClassBytes(GodzillaShellToolProvider.class);
        assertFalse(contains(origin, "javax/websocket"));
        assertFalse(contains(origin, "javax/servlet"));
        byte[] patched = rewriteConstantPool(GodzillaRawWebSocket.class, origin);
        assertArrayEquals(origin, patched);
    }

    @Test
    void patchIsNoOpOnJavaxClasspath() {
        // 测试类路径上 javax.servlet 存在（javax 容器语义），payload 原样返回
        byte[] origin = readClassBytes(GodzillaWebSocket.class);
        assertSame(origin, GodzillaRawWebSocket.patchPayloadNamespace(origin));
        assertSame(origin, GodzillaWebSocket.patchPayloadNamespace(origin));
    }

    private static byte[] readClassBytes(Class<?> clazz) {
        String path = clazz.getName().replace('.', '/') + ".class";
        try {
            InputStream in = clazz.getClassLoader().getResourceAsStream(path);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            in.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] rewriteConstantPool(Class<?> template, byte[] data) throws Exception {
        Method method = template.getDeclaredMethod("rewriteConstantPool", byte[].class);
        method.setAccessible(true);
        return (byte[]) method.invoke(null, data);
    }

    private static boolean contains(byte[] data, String needle) {
        byte[] n = needle.getBytes();
        for (int i = 0; i + n.length <= data.length; i++) {
            boolean found = true;
            for (int j = 0; j < n.length; j++) {
                if (data[i + j] != n[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }
}
