package com.reajason.javaweb.memshell.shelltool.wsproxy;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    void connectFailureSends503AndCloses() throws IOException {
        shell.onReadBinary(helper, ("CONNECT 127.0.0.1:" + unusedPort()).getBytes(UTF8));

        assertEquals(Collections.singletonList("HTTP/1.1 503 Service Unavailable\r\n\r\n"), helper.texts);
        assertTrue(helper.closed, "failed CONNECT must close the websocket");
        assertNull(helper.getAttribute("socket"));
    }

    @Test
    void malformedConnectSends400AndCloses() {
        shell.onReadBinary(helper, "CONNECT".getBytes(UTF8));

        assertEquals(Collections.singletonList("HTTP/1.1 400 Bad Request\r\n\r\n"), helper.texts);
        assertTrue(helper.closed, "malformed CONNECT must close the websocket");
    }

    @Test
    void successfulConnectKeepsSessionOpenAndClosesTargetOnDisconnect() throws IOException {
        ServerSocket server = new ServerSocket(0);
        try {
            shell.onReadBinary(helper, ("CONNECT 127.0.0.1:" + server.getLocalPort()).getBytes(UTF8));

            assertEquals(Collections.singletonList("HTTP/1.1 200 Connection Established\r\n\r\n"), helper.texts);
            assertFalse(helper.closed, "successful CONNECT must keep the websocket open");
            Socket target = (Socket) helper.getAttribute("socket");
            assertNotNull(target);

            shell.onDisconnect(helper);
            assertTrue(target.isClosed(), "disconnect must release the target socket");
        } finally {
            server.close();
        }
    }

    private static int unusedPort() throws IOException {
        ServerSocket server = new ServerSocket(0);
        try {
            return server.getLocalPort();
        } finally {
            server.close();
        }
    }

    /**
     * 与 helper 暴露给壳的反射 API 同名同签名。
     */
    public static class FakeHelper {
        final List<String> texts = new ArrayList<String>();
        final Map<String, Object> attributes = new HashMap<String, Object>();
        boolean closed;

        public void sendText(String text) {
            texts.add(text);
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
