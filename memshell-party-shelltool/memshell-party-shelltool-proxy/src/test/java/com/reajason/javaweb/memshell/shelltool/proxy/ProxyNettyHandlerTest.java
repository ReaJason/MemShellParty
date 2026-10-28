package com.reajason.javaweb.memshell.shelltool.proxy;

import com.sun.net.httpserver.HttpServer;
import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassUtils;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPromise;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ReferenceCountUtil;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyNettyHandlerTest {

    @Test
    void generatedHandlerSupportsFragmentedPushesAcrossHttpConnections() {
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

        ProxyConfig toolConfig = ProxyConfig.builder()
                .shellTemplateClassName(ProxyNettyHandler.class.getName())
                .shellClassName("io.netty.channel.GeneratedProxyHandler")
                .headerName(ProxyPhtTestSupport.HEADER_NAME)
                .headerValue(ProxyPhtTestSupport.HEADER_VALUE)
                .build();
        byte[] shellBytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.SpringWebFlux)
                .shellType(ShellType.NETTY_HANDLER)
                .targetJreVersion(Opcodes.V1_8)
                .build(), toolConfig).getBytes();
        ChannelHandler proxy = (ChannelHandler) ClassUtils.newInstance(shellBytes);

        NioEventLoopGroup eventLoop = new NioEventLoopGroup(1);
        Channel server = null;
        try {
            server = new ServerBootstrap()
                    .group(eventLoop)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel channel) {
                            channel.pipeline().addLast("http", new HttpServerCodec());
                            channel.pipeline().addLast("proxy", proxy);
                            // Reactor's response handlers must not see responses to requests consumed above.
                            channel.pipeline().addLast("downstream-response-filter", new ChannelDuplexHandler() {
                                private int pendingRequests;

                                @Override
                                public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                    if (msg instanceof HttpRequest) {
                                        pendingRequests++;
                                    }
                                    ctx.fireChannelRead(msg);
                                }

                                @Override
                                public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
                                    if (pendingRequests > 0) {
                                        if (msg instanceof FullHttpResponse) {
                                            pendingRequests--;
                                        }
                                        ctx.write(msg, promise);
                                    } else {
                                        ReferenceCountUtil.release(msg);
                                        promise.setSuccess();
                                    }
                                }
                            });
                            channel.pipeline().addLast("ordinary", new SimpleChannelInboundHandler<LastHttpContent>() {
                                @Override
                                protected void channelRead0(ChannelHandlerContext context, LastHttpContent content) {
                                    FullHttpResponse response = new DefaultFullHttpResponse(
                                            HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                            Unpooled.copiedBuffer("pht-ok", StandardCharsets.US_ASCII));
                                    response.headers().set(HttpHeaderNames.CONTENT_LENGTH,
                                            response.content().readableBytes());
                                    response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
                                    context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
                                }
                            });
                        }
                    })
                    .bind(new InetSocketAddress("127.0.0.1", 0))
                    .sync()
                    .channel();

            String base = "http://127.0.0.1:" + ((InetSocketAddress) server.localAddress()).getPort();
            HttpURLConnection ordinaryRequest = ProxyPhtTestSupport.connection(base + "/", "GET");
            assertEquals(200, ordinaryRequest.getResponseCode());
            assertEquals("pht-ok", new String(ProxyPhtTestSupport.readAll(
                    ordinaryRequest.getInputStream()), StandardCharsets.US_ASCII));
            ordinaryRequest.disconnect();

            ProxyPhtTestSupport.verifyClientTokenTunnel(base + "/proxy", target.getAddress().getPort(), true);
            ProxyPhtTestSupport.verifyClientTokenTunnel(base + "/proxy",
                    ((InetSocketAddress) server.localAddress()).getPort(), true);
            verifyPullDisconnectClosesSession(base, proxy);
            ProxyPhtTestSupport.assertBoundedDaemonExecutor(proxy, "HTTP_EXECUTOR");
        } finally {
            if (server != null) {
                server.close().sync();
            }
            eventLoop.shutdownGracefully(0, 0, TimeUnit.SECONDS).sync();
            target.stop(0);
        }
    }

    private static void verifyPullDisconnectClosesSession(String base, ChannelHandler proxy) throws Exception {
        String token = ProxyPhtTestSupport.authorize(base + "/proxy");
        java.net.URL url = new java.net.URL(base);
        try (Socket socket = new Socket(url.getHost(), url.getPort())) {
            socket.setSoTimeout(15000);
            OutputStream output = socket.getOutputStream();
            output.write(("GET /proxy?token=" + token + " HTTP/1.1\r\n"
                    + "Host: " + url.getHost() + ":" + url.getPort() + "\r\n"
                    + ProxyPhtTestSupport.HEADER_NAME + ": " + ProxyPhtTestSupport.HEADER_VALUE + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            output.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            String status = reader.readLine();
            assertNotNull(status);
            assertTrue(status.startsWith("HTTP/1.1 200 "), status);
            while (true) {
                String line = reader.readLine();
                assertNotNull(line);
                if (line.isEmpty()) {
                    break;
                }
            }
        }

        Field field = proxy.getClass().getDeclaredField("proxyHttpClass");
        field.setAccessible(true);
        Class<?> core = (Class<?>) field.get(null);
        Object session = core.getMethod("getSession", String.class).invoke(null, token);
        assertNotNull(session);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        boolean closed = false;
        while (System.nanoTime() < deadline && !closed) {
            closed = Boolean.TRUE.equals(core.getMethod("isClosed").invoke(session));
            if (!closed) {
                Thread.sleep(10);
            }
        }
        assertTrue(closed, "Closing the pull connection must close its proxy session");
    }
}
