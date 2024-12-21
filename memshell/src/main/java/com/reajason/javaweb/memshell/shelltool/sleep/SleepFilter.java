package com.reajason.javaweb.memshell.shelltool.sleep;

import javax.servlet.*;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class SleepFilter implements Filter {
    private int second = 10;

    @Override
    public void destroy() {

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            Thread.sleep(second * 1000);
        } catch (InterruptedException ignored) {

        }
    }
}
