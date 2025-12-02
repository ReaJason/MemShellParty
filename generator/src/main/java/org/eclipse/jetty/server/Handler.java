package org.eclipse.jetty.server;

import org.eclipse.jetty.util.Callback;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/11/29
 */
public interface Handler {
    void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException;

    boolean handle(Request request, Response response, Callback callback) throws Exception;

    void handle(String target, HttpServletRequest request, HttpServletResponse response, int dispatch) throws IOException, ServletException;
}
