package com.reajason.javaweb.memshell.shelltool.proxy;

import com.sun.net.httpserver.HttpServer;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.server.jetty.Jetty;
import com.reajason.javaweb.utils.ClassUtils;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class ProxyJetty12HandlerTest {

    @Test
    void generatedHandlerForwardsHttpConnectAndPassesOrdinaryTraffic() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), this::verifyServer);
    }

    private void verifyServer() throws Exception {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        target.createContext("/", exchange -> {
            byte[] body = "pht-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        target.start();

        Class<?> serverClass = Class.forName("org.eclipse.jetty.server.Server");
        Class<?> handlerClass = Class.forName("org.eclipse.jetty.server.Handler");
        Object server = serverClass.newInstance();
        Object connector = Class.forName("org.eclipse.jetty.server.ServerConnector")
                .getConstructor(serverClass).newInstance(server);
        connector.getClass().getMethod("setHost", String.class).invoke(connector, "127.0.0.1");
        connector.getClass().getMethod("setPort", int.class).invoke(connector, 0);
        serverClass.getMethod("addConnector", Class.forName("org.eclipse.jetty.server.Connector"))
                .invoke(server, connector);
        try {
            ProxyConfig toolConfig = ProxyConfig.builder()
                    .shellTemplateClassName(ProxyJettyHandler.class.getName())
                    .shellClassName("org.eclipse.jetty.server.GeneratedProxyHandler")
                    .headerName(ProxyPhtTestSupport.HEADER_NAME)
                    .headerValue(ProxyPhtTestSupport.HEADER_VALUE)
                    .build();
            ShellConfig shellConfig = ShellConfig.builder()
                    .server(Server.Jetty)
                    .shellType(ShellType.HANDLER)
                    .serverVersion("12")
                    .build();
            byte[] shellBytes = new ProxyGenerator(shellConfig, toolConfig).getBytes();
            shellBytes = new Jetty().postProcessShellBytes(
                    shellBytes, shellConfig, toolConfig, InjectorConfig.builder().build());
            Object shell = ClassUtils.newInstance(shellBytes);
            Object ordinary = Class.forName("org.eclipse.jetty.server.handler.DefaultHandler").newInstance();
            setField(shell, "nextHandler", ordinary);
            serverClass.getMethod("setHandler", handlerClass).invoke(server, shell);
            serverClass.getMethod("start").invoke(server);

            String base = "http://127.0.0.1:" + connector.getClass().getMethod("getLocalPort").invoke(connector);
            HttpURLConnection ordinaryRequest = ProxyPhtTestSupport.connection(base + "/", "GET");
            assertEquals(404, ordinaryRequest.getResponseCode());
            ordinaryRequest.disconnect();

            ProxyPhtTestSupport.verifyTunnel(base + "/proxy", target.getAddress().getPort());
            ProxyPhtTestSupport.verifyClientTokenTunnel(base + "/proxy", target.getAddress().getPort());
            ProxyPhtTestSupport.assertBoundedDaemonExecutor(shell, "JETTY12_EXECUTOR");
        } finally {
            serverClass.getMethod("stop").invoke(server);
            serverClass.getMethod("destroy").invoke(server);
            target.stop(0);
        }
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}
