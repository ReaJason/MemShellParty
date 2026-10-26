package com.reajason.javaweb.memshell.shelltool.wsproxy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 代理壳在 CONNECT 失败时必须回错误响应并主动关闭 helper 会话，
 * 否则 helper 的帧循环会一直挂在读上。
 *
 * @author ReaJason
 */
class ProxyRawWebSocketTest {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private final ProxyRawWebSocket shell = new ProxyRawWebSocket();
    private final FakeHelper helper = new FakeHelper();

    @Test
    void connectFailureSendsBinary503AndCloses() throws IOException {
        shell.onReadBinary(helper, ("CONNECT 127.0.0.1:" + unusedPort()).getBytes(UTF8));

        assertResponse(helper, "503 Service Unavailable");
        assertTrue(helper.closed, "failed CONNECT must close the websocket");
        assertNull(helper.getAttribute("socket"));
    }

    @Test
    void malformedConnectSendsBinary400AndCloses() {
        shell.onReadBinary(helper, "CONNECT".getBytes(UTF8));

        assertResponse(helper, "400 Bad Request");
        assertTrue(helper.closed, "malformed CONNECT must close the websocket");
    }

    @Test
    void successfulConnectSendsBinary200AndClosesTargetOnDisconnect() throws IOException {
        ServerSocket server = new ServerSocket(0);
        try {
            shell.onReadBinary(helper, ("CONNECT 127.0.0.1:" + server.getLocalPort()).getBytes(UTF8));

            assertResponse(helper, "200 Connection Established");
            assertFalse(helper.closed, "successful CONNECT must keep the websocket open");
            Socket target = (Socket) helper.getAttribute("socket");
            assertNotNull(target);

            shell.onDisconnect(helper);
            assertTrue(target.isClosed(), "disconnect must release the target socket");
        } finally {
            server.close();
        }
    }

    @Test
    void acceptsBracketedIpv6Target() throws IOException {
        TestSocket target = new TestSocket();
        ProxyRawWebSocket shell = new TestProxyRawWebSocket(target);
        FakeHelper helper = new FakeHelper();
        try {
            shell.onReadBinary(helper, "CONNECT [::1]:443".getBytes(UTF8));

            assertResponse(helper, "200 Connection Established");
            InetSocketAddress remote = (InetSocketAddress) target.remote;
            assertEquals(InetAddress.getByName("::1"), remote.getAddress());
            assertEquals(443, remote.getPort());
        } finally {
            shell.onDisconnect(helper);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-port", "0", "65536"})
    void rejectsInvalidPortWithBinary400(String port) {
        shell.onReadBinary(helper, ("CONNECT 127.0.0.1:" + port).getBytes(UTF8));

        assertResponse(helper, "400 Bad Request");
        assertTrue(helper.closed, "invalid CONNECT must close the websocket");
    }

    @Test
    void targetWriteFailureClosesTunnel() throws IOException {
        TestSocket target = new TestSocket();
        target.output = new OutputStream() {
            @Override
            public void write(int value) throws IOException {
                throw new IOException("broken target connection");
            }
        };
        helper.setAttribute("socket", target);

        shell.onReadBinary(helper, "payload".getBytes(UTF8));

        assertTrue(target.closed, "a failed target write must close the target socket");
        assertTrue(helper.closed, "a failed target write must close the websocket");
    }

    private static void assertResponse(FakeHelper helper, String status) {
        assertTrue(helper.texts.isEmpty(), "proxy responses must use binary frames");
        assertEquals(1, helper.binaries.size());
        assertArrayEquals(("HTTP/1.1 " + status + "\r\n\r\n").getBytes(UTF8), helper.binaries.get(0));
    }

    private static int unusedPort() throws IOException {
        ServerSocket server = new ServerSocket(0);
        try {
            return server.getLocalPort();
        } finally {
            server.close();
        }
    }

    private static class TestProxyRawWebSocket extends ProxyRawWebSocket {
        private final Socket socket;

        TestProxyRawWebSocket(Socket socket) {
            this.socket = socket;
        }

        @Override
        Socket createSocket() {
            return socket;
        }
    }

    private static class TestSocket extends Socket {
        SocketAddress remote;
        OutputStream output = new ByteArrayOutputStream();
        boolean closed;

        @Override
        public void connect(SocketAddress remote, int timeout) {
            this.remote = remote;
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(new byte[0]);
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    /**
     * 与 helper 暴露给壳的反射 API 同名同签名。
     */
    public static class FakeHelper {
        final List<String> texts = new ArrayList<String>();
        final List<byte[]> binaries = new ArrayList<byte[]>();
        final Map<String, Object> attributes = new HashMap<String, Object>();
        boolean closed;

        public void sendText(String text) {
            texts.add(text);
        }

        public void sendBinary(byte[] data) {
            binaries.add(data);
        }

        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        public void setAttribute(String name, Object value) {
            attributes.put(name, value);
        }

        public void startPump(InputStream inputStream) {
        }

        public void close() {
            closed = true;
        }
    }
}
