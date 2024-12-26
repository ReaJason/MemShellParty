package com.tongweb.web.thor;

import com.tongweb.web.thor.comet.CometEvent;
import com.tongweb.web.thor.connector.Request;
import com.tongweb.web.thor.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

public interface Valve {
    String getInfo();

    Valve getNext();

    void setNext(Valve var1);

    void backgroundProcess();

    void invoke(Request var1, Response var2) throws IOException, ServletException;

    void event(Request var1, Response var2, CometEvent var3) throws IOException, ServletException;

    boolean isAsyncSupported();
}
