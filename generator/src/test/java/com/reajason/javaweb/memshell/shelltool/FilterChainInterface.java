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
public interface FilterChainInterface {
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException;

    void doFilterInternal();
}
