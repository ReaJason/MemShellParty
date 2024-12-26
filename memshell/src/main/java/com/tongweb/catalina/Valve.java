package com.tongweb.catalina;

import com.tongweb.catalina.connector.Request;
import com.tongweb.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

public interface Valve {
    Valve getNext();

    void setNext(Valve var1);

    void backgroundProcess();

    void invoke(Request var1, Response var2) throws IOException, ServletException;

    boolean isAsyncSupported();
}
