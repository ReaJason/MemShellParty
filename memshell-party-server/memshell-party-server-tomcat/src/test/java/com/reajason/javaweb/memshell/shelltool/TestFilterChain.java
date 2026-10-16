package com.reajason.javaweb.memshell.shelltool;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/3/30
 */
public class TestFilterChain implements FilterChainInterface {

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilterInternal();
    }

    public void doFilterInternal() {
        System.out.println("doFilterInternal");
    }
}
