package com.bes.enterprise.webtier;

import com.bes.enterprise.webtier.connector.Request;
import com.bes.enterprise.webtier.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

public interface Valve {
    Valve getNext();

    void setNext(Valve var1);

    void backgroundProcess();

    void invoke(Request var1, Response var2) throws IOException, ServletException;

    boolean isAsyncSupported();
}