package com.xxl.job.core.server;

import com.xxl.job.core.biz.ExecutorBiz;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;

import java.util.concurrent.ThreadPoolExecutor;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class EmbedServer {

    public static class EmbedHttpServerHandler implements ChannelHandler {
        public EmbedHttpServerHandler(ExecutorBiz executorBiz, String prefix, ThreadPoolExecutor executor) {

        }

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) throws Exception {

        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {

        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {

        }
    }
}
