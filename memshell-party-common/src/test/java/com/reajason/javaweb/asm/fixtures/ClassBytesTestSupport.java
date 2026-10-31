package com.reajason.javaweb.asm.fixtures;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 字节码测试公用工具：读取 class 字节、子优先加载改写后的类、提取异常消息。
 */
public final class ClassBytesTestSupport {

    private ClassBytesTestSupport() {
    }

    public static byte[] read(Class<?> type) throws Exception {
        String resource = type.getSimpleName() + ".class";
        InputStream in = type.getResourceAsStream(resource);
        assertNotNull(in, "找不到类字节：" + resource);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /**
     * 子优先加载：测试类路径上也有同名类，必须让改写后的字节覆盖它。
     */
    public static Class<?> load(final String binaryName, final byte[] bytes) throws Exception {
        ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
        ClassLoader loader = new ClassLoader(parent) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (!binaryName.equals(name)) {
                    return super.loadClass(name, resolve);
                }
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    loaded = defineClass(name, bytes, 0, bytes.length);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        };
        return Class.forName(binaryName, true, loader);
    }

    public static String messageOf(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException ex) {
            return ex.getMessage() == null ? "" : ex.getMessage();
        }
        throw new AssertionError("应当抛出 IllegalArgumentException");
    }
}
