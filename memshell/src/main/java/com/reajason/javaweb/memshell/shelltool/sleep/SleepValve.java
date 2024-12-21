package com.reajason.javaweb.memshell.shelltool.sleep;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class SleepValve implements Valve {
    private int second = 10;

    @Override
    public Valve getNext() {
        return null;
    }

    @Override
    public void setNext(Valve valve) {

    }

    @Override
    public void backgroundProcess() {

    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            Thread.sleep(second * 1000);
        } catch (InterruptedException ignored) {

        }
    }

    @Override
    public boolean isAsyncSupported() {
        return false;
    }
}
