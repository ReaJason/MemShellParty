package org.apache.catalina;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public interface Valve {

    public Valve getNext();

    public void setNext(Valve valve);

    public void backgroundProcess();

    public void invoke(Request request, Response response)
            throws IOException, ServletException;

    public boolean isAsyncSupported();
}
