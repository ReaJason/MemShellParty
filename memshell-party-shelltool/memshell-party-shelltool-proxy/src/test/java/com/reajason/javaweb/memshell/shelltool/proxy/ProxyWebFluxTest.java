package com.reajason.javaweb.memshell.shelltool.proxy;

import com.sun.net.httpserver.HttpServer;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassUtils;
import io.netty.channel.ChannelHandler;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.HttpWebHandlerAdapter;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.resources.LoopResources;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class ProxyWebFluxTest {

    enum Mode {
        WEB_FILTER,
        HANDLER_METHOD,
        HANDLER_FUNCTION,
        NETTY_HANDLER
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void generatedEntryPointForwardsHttpConnect(Mode mode) {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> verifyServer(mode));
    }

    private void verifyServer(Mode mode) throws Exception {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        target.createContext("/", exchange -> {
            byte[] body = "pht-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        target.start();

        AnnotationConfigApplicationContext context = null;
        DisposableServer server = null;
        LoopResources eventLoop = LoopResources.create("proxy-test", 1, true);
        try {
            Object shell = generate(mode);
            HttpHandler httpHandler;
            if (mode == Mode.HANDLER_METHOD) {
                context = new AnnotationConfigApplicationContext();
                context.register(WebFluxConfiguration.class);
                context.getBeanFactory().registerSingleton("generatedProxy", shell);
                context.refresh();
                RequestMappingHandlerMapping mapping = context.getBean(RequestMappingHandlerMapping.class);
                Method invoke = shell.getClass().getMethod("invoke", ServerWebExchange.class);
                mapping.registerMapping(RequestMappingInfo.paths("/**").build(), shell, invoke);
                httpHandler = WebHttpHandlerBuilder.applicationContext(context).build();
            } else if (mode == Mode.HANDLER_FUNCTION) {
                @SuppressWarnings("unchecked")
                HandlerFunction<ServerResponse> function = (HandlerFunction<ServerResponse>) shell;
                httpHandler = RouterFunctions.toHttpHandler(
                        RouterFunctions.route(RequestPredicates.all(), function));
            } else if (mode == Mode.WEB_FILTER) {
                WebFilter filter = (WebFilter) shell;
                WebHandler handler = exchange -> filter.filter(exchange, chain -> ordinary(exchange));
                httpHandler = new HttpWebHandlerAdapter(handler);
            } else {
                httpHandler = new HttpWebHandlerAdapter(ProxyWebFluxTest::ordinary);
            }

            reactor.netty.http.server.HttpServer httpServer = reactor.netty.http.server.HttpServer.create()
                    .host("127.0.0.1")
                    .port(0)
                    .runOn(eventLoop)
                    .handle(new ReactorHttpHandlerAdapter(httpHandler));
            if (mode == Mode.NETTY_HANDLER) {
                httpServer = httpServer.doOnChannelInit((observer, channel, remoteAddress) ->
                        channel.pipeline().addBefore("reactor.left.httpTrafficHandler", "proxy",
                                (ChannelHandler) shell));
            }
            server = httpServer.bindNow(Duration.ofSeconds(5));
            String base = "http://127.0.0.1:" + server.port();

            assertOrdinaryResponse(base, mode);
            ProxyPhtTestSupport.verifyClientTokenTunnel(base + "/proxy", target.getAddress().getPort());
            verifyIdlePullDoesNotBlockEventLoop(base, target.getAddress().getPort(), mode);
        } finally {
            if (server != null) {
                server.disposeNow(Duration.ofSeconds(5));
            }
            eventLoop.disposeLater().block(Duration.ofSeconds(5));
            if (context != null) {
                context.close();
            }
            target.stop(0);
        }
    }

    private static void assertOrdinaryResponse(String base, Mode mode) throws Exception {
        HttpURLConnection request = ProxyPhtTestSupport.connection(base + "/", "GET");
        request.setReadTimeout(2000);
        try {
            int expectedStatus = mode == Mode.HANDLER_METHOD ? 404 : 200;
            assertEquals(expectedStatus, request.getResponseCode());
            if (expectedStatus == 200) {
                String body = new String(ProxyPhtTestSupport.readAll(
                        request.getInputStream()), StandardCharsets.US_ASCII);
                assertEquals(mode == Mode.HANDLER_FUNCTION ? "" : "ordinary", body);
            }
        } finally {
            request.disconnect();
        }
    }

    private static void verifyIdlePullDoesNotBlockEventLoop(String base, int targetPort,
                                                            Mode mode) throws Exception {
        String endpoint = base + "/proxy";
        String token = ProxyPhtTestSupport.authorize(endpoint);
        String connect = "CONNECT 127.0.0.1:" + targetPort + " HTTP/1.1\r\n\r\n";
        ProxyPhtTestSupport.push(endpoint, token, connect.getBytes(StandardCharsets.ISO_8859_1), false);
        HttpURLConnection pull = ProxyPhtTestSupport.connection(endpoint + "?token=" + token, "GET");
        try {
            assertEquals(200, pull.getResponseCode());
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    pull.getInputStream(), StandardCharsets.US_ASCII));
            String established = null;
            while (established == null) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                if (!line.isEmpty()) {
                    established = new String(Base64.getDecoder().decode(line), StandardCharsets.ISO_8859_1);
                }
            }
            assertEquals("HTTP/1.1 200 Connection Established\r\n\r\n", established);
            assertOrdinaryResponse(base, mode);
        } finally {
            pull.disconnect();
        }
    }

    private static Object generate(Mode mode) {
        String template;
        String shellType;
        String className;
        if (mode == Mode.NETTY_HANDLER) {
            template = ProxyNettyHandler.class.getName();
            shellType = ShellType.NETTY_HANDLER;
            className = null;
        } else if (mode == Mode.HANDLER_METHOD) {
            template = ProxyHandlerMethod.class.getName();
            shellType = ShellType.SPRING_WEBFLUX_HANDLER_METHOD;
            className = "org.springframework.web.reactive.GeneratedProxyHandlerMethod";
        } else if (mode == Mode.HANDLER_FUNCTION) {
            template = ProxyHandlerFunction.class.getName();
            shellType = ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION;
            className = "org.springframework.web.reactive.GeneratedProxyHandlerFunction";
        } else {
            template = ProxyWebFilter.class.getName();
            shellType = ShellType.SPRING_WEBFLUX_WEB_FILTER;
            className = "org.springframework.web.reactive.GeneratedProxyWebFilter";
        }
        ProxyConfig toolConfig = ProxyConfig.builder()
                .shellTemplateClassName(template)
                .shellClassName(className)
                .headerName(ProxyPhtTestSupport.HEADER_NAME)
                .headerValue(ProxyPhtTestSupport.HEADER_VALUE)
                .build();
        if (mode == Mode.NETTY_HANDLER) {
            ShellConfig shellConfig = ShellConfig.builder()
                    .server(Server.SpringWebFlux)
                    .serverVersion("unknown")
                    .shellTool(ShellTool.Proxy)
                    .shellType(shellType)
                    .targetJreVersion(Opcodes.V1_8)
                    .byPassJavaModule(false)
                    .debug(true)
                    .shrink(true)
                    .lambdaSuffix(true)
                    .obfuscation(ObfuscationConfig.enabled())
                    .build();
            byte[] shellBytes = new MemShellGenerator().generate(shellConfig,
                    InjectorConfig.builder().staticInitialize(true).build(), toolConfig).getShellBytes();
            return ClassUtils.newInstance(shellBytes);
        }
        byte[] shellBytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.SpringWebFlux)
                .shellType(shellType)
                .targetJreVersion(Opcodes.V1_8)
                .build(), toolConfig).getBytes();
        return ClassUtils.newInstance(shellBytes);
    }

    private static Mono<Void> ordinary(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        byte[] body = "ordinary".getBytes(StandardCharsets.US_ASCII);
        response.getHeaders().setContentLength(body.length);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    @Configuration
    @EnableWebFlux
    static class WebFluxConfiguration {
    }
}
