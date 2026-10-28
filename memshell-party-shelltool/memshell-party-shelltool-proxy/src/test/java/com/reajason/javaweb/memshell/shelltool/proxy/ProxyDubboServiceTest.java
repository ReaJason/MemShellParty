package com.reajason.javaweb.memshell.shelltool.proxy;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.ClassUtils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyDubboServiceTest {

    @Test
    void generatedServiceForwardsConnectAndPayloads() {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try (ServerSocket server = new ServerSocket(0)) {
                executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        InputStream input = socket.getInputStream();
                        OutputStream output = socket.getOutputStream();
                        byte[] buffer = new byte[4096];
                        int count;
                        while ((count = input.read(buffer)) >= 0) {
                            output.write(buffer, 0, count);
                            output.flush();
                        }
                    } catch (Exception ignored) {
                    }
                });

                Object shell = newShell();
                Method handle = shell.getClass().getMethod("handle", byte[].class);
                DataInputStream created = response((byte[]) handle.invoke(shell, (Object) new byte[]{0}));
                assertEquals(0, created.read());
                String token = created.readUTF();

                String connect = "CONNECT 127.0.0.1:" + server.getLocalPort() + " HTTP/1.1\r\n\r\n";
                assertEquals(0, push(handle, shell, token,
                        connect.getBytes(StandardCharsets.ISO_8859_1)));
                assertArrayEquals("HTTP/1.1 200 Connection Established\r\n\r\n"
                                .getBytes(StandardCharsets.ISO_8859_1),
                        pull(handle, shell, token));

                byte[] first = "first-payload".getBytes(StandardCharsets.ISO_8859_1);
                assertEquals(0, push(handle, shell, token, first));
                assertArrayEquals(first, pull(handle, shell, token));
                byte[] second = "second-payload".getBytes(StandardCharsets.ISO_8859_1);
                assertEquals(0, push(handle, shell, token, second));
                assertArrayEquals(second, pull(handle, shell, token));

                assertEquals(0, operation(handle, shell, 3, token));
                DataInputStream ended = response((byte[]) handle.invoke(shell,
                        (Object) tokenRequest(2, token)));
                assertEquals(0, ended.read());
                assertEquals(0, ended.readInt());
                assertTrue(push(handle, shell, token, first) != 0);
            } finally {
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            }
        });
    }

    @Test
    void generatedServiceForwardsHalfCloseBeforeResponse() {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try (ServerSocket server = new ServerSocket(0)) {
                final byte[] response = "response-after-upload-eof".getBytes(StandardCharsets.ISO_8859_1);
                Future<byte[]> targetWorker = executor.submit(() -> {
                    try (Socket socket = server.accept()) {
                        InputStream input = socket.getInputStream();
                        ByteArrayOutputStream received = new ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int count;
                        while ((count = input.read(buffer)) >= 0) {
                            received.write(buffer, 0, count);
                        }
                        socket.getOutputStream().write(response);
                        socket.getOutputStream().flush();
                        return received.toByteArray();
                    }
                });

                Object shell = newShell();
                Method handle = shell.getClass().getMethod("handle", byte[].class);
                DataInputStream created = response((byte[]) handle.invoke(shell, (Object) new byte[]{0}));
                assertEquals(0, created.read());
                String token = created.readUTF();
                try {
                    String connect = "CONNECT 127.0.0.1:" + server.getLocalPort() + " HTTP/1.1\r\n\r\n";
                    assertEquals(0, push(handle, shell, token,
                            connect.getBytes(StandardCharsets.ISO_8859_1)));
                    assertArrayEquals("HTTP/1.1 200 Connection Established\r\n\r\n"
                                    .getBytes(StandardCharsets.ISO_8859_1),
                            pull(handle, shell, token));

                    byte[] upload = "upload-body".getBytes(StandardCharsets.ISO_8859_1);
                    assertEquals(0, push(handle, shell, token, upload));
                    assertEquals(0, operation(handle, shell, 4, token));
                    assertArrayEquals(response, pull(handle, shell, token));
                    DataInputStream ended = response((byte[]) handle.invoke(shell,
                            (Object) tokenRequest(2, token)));
                    assertEquals(0, ended.read());
                    assertEquals(0, ended.readInt());
                    assertArrayEquals(upload, targetWorker.get(5, TimeUnit.SECONDS));
                } finally {
                    operation(handle, shell, 3, token);
                    targetWorker.cancel(true);
                }
            } finally {
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            }
        });
    }

    private static Object newShell() {
        ProxyConfig config = ProxyConfig.builder()
                .shellTemplateClassName(ProxyDubboService.class.getName())
                .shellClassName("org.apache.utils.GeneratedProxyDubboService")
                .build();
        byte[] bytes = new ProxyGenerator(ShellConfig.builder()
                .server(Server.Dubbo)
                .shellType(ShellType.ALIBABA_DUBBO_SERVICE)
                .build(), config).getBytes();
        return ClassUtils.newInstance(bytes);
    }

    private static int push(Method handle, Object shell, String token, byte[] payload) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeByte(1);
        output.writeUTF(token);
        output.writeInt(payload.length);
        output.write(payload);
        output.flush();
        DataInputStream response = response((byte[]) handle.invoke(shell,
                (Object) buffer.toByteArray()));
        return response.read();
    }

    private static byte[] pull(Method handle, Object shell, String token) throws Exception {
        DataInputStream response = response((byte[]) handle.invoke(shell,
                (Object) tokenRequest(2, token)));
        assertEquals(0, response.read());
        int length = response.readInt();
        assertTrue(length > 0);
        byte[] data = new byte[length];
        response.readFully(data);
        return data;
    }

    private static int operation(Method handle, Object shell, int operation, String token) throws Exception {
        DataInputStream response = response((byte[]) handle.invoke(shell,
                (Object) tokenRequest(operation, token)));
        return response.read();
    }

    private static byte[] tokenRequest(int operation, String token) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeByte(operation);
        output.writeUTF(token);
        output.flush();
        return buffer.toByteArray();
    }

    private static DataInputStream response(byte[] bytes) {
        return new DataInputStream(new ByteArrayInputStream(bytes));
    }
}
