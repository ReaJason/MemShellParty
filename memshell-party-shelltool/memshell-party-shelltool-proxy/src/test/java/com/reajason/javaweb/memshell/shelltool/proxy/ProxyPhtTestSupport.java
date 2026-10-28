package com.reajason.javaweb.memshell.shelltool.proxy;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ProxyPhtTestSupport {
    static final String HEADER_NAME = "X-Proxy-Test";
    static final String HEADER_VALUE = "pht-test";

    private ProxyPhtTestSupport() {
    }

    static void verifyTunnel(String endpoint, int targetPort) throws Exception {
        verifyTunnel(endpoint, targetPort, false);
    }

    static void verifyTunnel(String endpoint, int targetPort, boolean fragmentedPush) throws Exception {
        String token = authorize(endpoint);
        verifyTunnelSession(endpoint, targetPort, token, fragmentedPush, HEADER_NAME, HEADER_VALUE);
    }

    static void verifyClientTokenTunnel(String endpoint, int targetPort) throws Exception {
        verifyClientTokenTunnel(endpoint, targetPort, false);
    }

    static void verifyClientTokenTunnel(String endpoint, int targetPort, boolean fragmentedPush) throws Exception {
        verifyTunnelSession(endpoint, targetPort, UUID.randomUUID().toString(), fragmentedPush,
                HEADER_NAME, HEADER_VALUE);
    }

    static void verifyTunnelSession(String endpoint, int targetPort, String token, boolean fragmentedPush,
                                    String headerName, String headerValue) throws Exception {
        HttpURLConnection pull = null;
        try {
            String connect = "CONNECT 127.0.0.1:" + targetPort + " HTTP/1.1\r\n\r\n";
            push(endpoint, token, connect.getBytes(StandardCharsets.ISO_8859_1), fragmentedPush,
                    headerName, headerValue);

            pull = connection(endpoint + "?token=" + token, "GET", headerName, headerValue);
            assertEquals(200, pull.getResponseCode());
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    pull.getInputStream(), StandardCharsets.US_ASCII));
            String established = new String(Base64.getDecoder().decode(nextDataLine(reader)),
                    StandardCharsets.ISO_8859_1);
            assertEquals("HTTP/1.1 200 Connection Established\r\n\r\n", established);

            String request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            push(endpoint, token, request.getBytes(StandardCharsets.ISO_8859_1), fragmentedPush,
                    headerName, headerValue);
            ByteArrayOutputStream targetResponse = new ByteArrayOutputStream();
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    targetResponse.write(Base64.getDecoder().decode(line));
                }
            }
            String response = new String(targetResponse.toByteArray(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertTrue(response.endsWith("pht-ok"), response);
        } finally {
            if (pull != null) {
                pull.disconnect();
            }
        }
    }

    static String authorize(String endpoint) throws IOException {
        return authorize(endpoint, HEADER_NAME, HEADER_VALUE);
    }

    static String authorize(String endpoint, String headerName, String headerValue) throws IOException {
        HttpURLConnection connection = connection(endpoint + "?token=", "GET", headerName, headerValue);
        try {
            assertEquals(200, connection.getResponseCode());
            String authorization = new String(readAll(connection.getInputStream()), StandardCharsets.US_ASCII);
            assertTrue(authorization.startsWith("token="), authorization);
            return authorization.substring("token=".length());
        } finally {
            connection.disconnect();
        }
    }

    static void push(String endpoint, String token, byte[] data, boolean fragmented) throws IOException {
        push(endpoint, token, data, fragmented, HEADER_NAME, HEADER_VALUE);
    }

    static void push(String endpoint, String token, byte[] data, boolean fragmented,
                     String headerName, String headerValue) throws IOException {
        if (fragmented) {
            fragmentedPush(endpoint, token, Base64.getEncoder().encode(data), headerName, headerValue);
            return;
        }
        byte[] body = Base64.getEncoder().encode(data);
        HttpURLConnection connection = connection(endpoint + "?token=" + token, "POST", headerName, headerValue);
        try {
            connection.setRequestProperty("Connection", "close");
            connection.setFixedLengthStreamingMode(body.length);
            connection.setDoOutput(true);
            OutputStream output = connection.getOutputStream();
            output.write(body);
            output.flush();
            assertEquals(200, connection.getResponseCode());
        } finally {
            connection.disconnect();
        }
    }

    private static void fragmentedPush(String endpoint, String token, byte[] body,
                                       String headerName, String headerValue) throws IOException {
        URL url = new URL(endpoint);
        int port = url.getPort() < 0 ? url.getDefaultPort() : url.getPort();
        try (Socket socket = new Socket(url.getHost(), port)) {
            socket.setSoTimeout(15000);
            OutputStream output = socket.getOutputStream();
            String path = url.getPath() + "?token=" + token;
            String headers = "POST " + path + " HTTP/1.1\r\n"
                    + "Host: " + url.getHost() + ":" + port + "\r\n"
                    + headerName + ": " + headerValue + "\r\n"
                    + "Content-Type: application/octet-stream\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Connection: close\r\n\r\n";
            output.write(headers.getBytes(StandardCharsets.US_ASCII));
            output.flush();
            int offset = 0;
            int[] fragments = {1, 2, 7, 3, 19};
            int index = 0;
            while (offset < body.length) {
                int count = Math.min(fragments[index++ % fragments.length], body.length - offset);
                output.write(body, offset, count);
                output.flush();
                offset += count;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            String status = reader.readLine();
            assertNotNull(status);
            assertTrue(status.startsWith("HTTP/1.1 200 "), status);
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                // Consume response headers before closing this push connection.
            }
        }
    }

    static void assertBoundedDaemonExecutor(Object shell, String fieldName) throws Exception {
        Field field = shell.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        ThreadPoolExecutor executor = (ThreadPoolExecutor) field.get(null);
        assertEquals(256, executor.getMaximumPoolSize());
        assertTrue(executor.getQueue() instanceof SynchronousQueue);
        assertTrue(executor.getRejectedExecutionHandler() instanceof ThreadPoolExecutor.AbortPolicy);
        Thread thread = executor.getThreadFactory().newThread(() -> {
        });
        assertTrue(thread.isDaemon());
    }

    static HttpURLConnection connection(String url, String method) throws IOException {
        return connection(url, method, HEADER_NAME, HEADER_VALUE);
    }

    static HttpURLConnection connection(String url, String method,
                                        String headerName, String headerValue) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty(headerName, headerValue);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(15000);
        return connection;
    }

    static byte[] readAll(InputStream input) throws IOException {
        assertNotNull(input);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static String nextDataLine(BufferedReader reader) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.isEmpty()) {
                return line;
            }
        }
        throw new IOException("PHT pull ended before downstream data arrived");
    }
}
