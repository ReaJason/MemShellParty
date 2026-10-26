package com.reajason.javaweb.memshell.shelltool.wsproxy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.websocket.RemoteEndpoint;
import javax.websocket.Session;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.net.SocketOption;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyWebSocketTest {

    @Test
    void writesAllBytesWhenSocketAcceptsPartialWrites() throws Exception {
        TestChannel target = new TestChannel(3, CompletableFuture.<Void>completedFuture(null));
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            shell.onMessage(connect("127.0.0.1:8080"));
            assertTrue(session.awaitResponse(), "CONNECT must receive a response");

            byte[] payload = "payload-after-connect".getBytes(StandardCharsets.ISO_8859_1);
            shell.onMessage(ByteBuffer.wrap(payload));

            assertArrayEquals(payload, target.writtenBytes());
            assertTrue(target.writeCount() > 1, "the test channel must force partial writes");
        } finally {
            shell.onClose(session.session, null);
        }
    }

    @Test
    void queuesDataUntilPendingConnectCompletes() throws Exception {
        CompletableFuture<Void> connected = new CompletableFuture<Void>();
        TestChannel target = new TestChannel(1024, connected);
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(1),
                    () -> shell.onMessage(connect("127.0.0.1:8080")));
            assertTrue(target.awaitConnect(), "the target connect must have started");

            byte[] payload = "data-while-connecting".getBytes(StandardCharsets.ISO_8859_1);
            shell.onMessage(ByteBuffer.wrap(payload));
            assertEquals(0, target.writtenBytes().length,
                    "data must wait until the target connection is established");

            connected.complete(null);
            assertTrue(session.awaitResponse(), "CONNECT must receive a response");
            assertTrue(target.awaitWrite(), "queued data must be flushed after CONNECT");
            assertResponse(session, "200 Connection Established");
            assertArrayEquals(payload, target.writtenBytes());
        } finally {
            connected.complete(null);
            shell.onClose(session.session, null);
        }
    }

    @Test
    void acceptsBracketedIpv6Target() throws Exception {
        TestChannel target = new TestChannel(1024, CompletableFuture.<Void>completedFuture(null));
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            shell.onMessage(connect("[::1]:443"));

            assertTrue(session.awaitResponse(), "IPv6 CONNECT must receive a response");
            assertResponse(session, "200 Connection Established");
            InetSocketAddress remote = (InetSocketAddress) target.remoteAddress;
            assertEquals(InetAddress.getByName("::1"), remote.getAddress());
            assertEquals(443, remote.getPort());
        } finally {
            shell.onClose(session.session, null);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-port", "0", "65536"})
    void rejectsInvalidPortWith400(String port) throws Exception {
        TestChannel target = new TestChannel(1024, CompletableFuture.<Void>completedFuture(null));
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            shell.onMessage(connect("127.0.0.1:" + port));

            assertTrue(session.awaitResponse(), "invalid ports must receive a response");
            assertResponse(session, "400 Bad Request");
            assertFalse(session.open, "invalid CONNECT must close the websocket");
        } finally {
            shell.onClose(session.session, null);
        }
    }

    @Test
    void failedConnectUsesBinary503Response() throws Exception {
        CompletableFuture<Void> failed = new CompletableFuture<Void>();
        failed.completeExceptionally(new IOException("connection refused"));
        TestChannel target = new TestChannel(1024, failed);
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            shell.onMessage(connect("127.0.0.1:8080"));

            assertTrue(session.awaitResponse(), "failed CONNECT must receive a response");
            assertResponse(session, "503 Service Unavailable");
            assertFalse(session.open, "failed CONNECT must close the websocket");
        } finally {
            shell.onClose(session.session, null);
        }
    }

    @Test
    void successfulConnectUsesBinary200Response() throws Exception {
        TestChannel target = new TestChannel(1024, CompletableFuture.<Void>completedFuture(null));
        TestProxyWebSocket shell = new TestProxyWebSocket(target);
        FakeSession session = new FakeSession();
        shell.onOpen(session.session, null);
        try {
            shell.onMessage(connect("127.0.0.1:8080"));

            assertTrue(session.awaitResponse(), "CONNECT must receive a response");
            assertResponse(session, "200 Connection Established");
            assertTrue(session.open, "successful CONNECT must keep the websocket open");
        } finally {
            shell.onClose(session.session, null);
        }
    }

    private static void assertResponse(FakeSession session, String status) {
        assertTrue(session.textFrames.isEmpty(), "proxy responses must use binary frames");
        assertEquals(1, session.binaryFrames.size());
        assertArrayEquals(("HTTP/1.1 " + status + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1),
                session.binaryFrames.get(0));
    }

    private static ByteBuffer connect(String address) {
        return ByteBuffer.wrap(("CONNECT " + address).getBytes(StandardCharsets.ISO_8859_1));
    }

    private static class TestProxyWebSocket extends ProxyWebSocket {
        private final AsynchronousSocketChannel channel;

        TestProxyWebSocket(AsynchronousSocketChannel channel) {
            this.channel = channel;
        }

        @Override
        AsynchronousSocketChannel openChannel() {
            return channel;
        }
    }

    private static class FakeSession implements InvocationHandler {
        final Session session;
        final RemoteEndpoint.Basic basicRemote;
        final List<String> textFrames = Collections.synchronizedList(new ArrayList<String>());
        final List<byte[]> binaryFrames = Collections.synchronizedList(new ArrayList<byte[]>());
        final CountDownLatch responseLatch = new CountDownLatch(1);
        volatile boolean open = true;

        FakeSession() {
            ClassLoader loader = getClass().getClassLoader();
            session = (Session) Proxy.newProxyInstance(loader, new Class<?>[]{Session.class}, this);
            basicRemote = (RemoteEndpoint.Basic) Proxy.newProxyInstance(
                    loader, new Class<?>[]{RemoteEndpoint.Basic.class}, this);
        }

        boolean awaitResponse() throws InterruptedException {
            return responseLatch.await(2, TimeUnit.SECONDS);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            if ("getBasicRemote".equals(name)) {
                return basicRemote;
            }
            if ("isOpen".equals(name)) {
                return open;
            }
            if ("close".equals(name) && proxy instanceof Session) {
                open = false;
                return null;
            }
            if ("sendText".equals(name) && args[0] instanceof String) {
                textFrames.add((String) args[0]);
                responseLatch.countDown();
                return null;
            }
            if ("sendBinary".equals(name)) {
                ByteBuffer data = (ByteBuffer) args[0];
                byte[] copy = new byte[data.remaining()];
                data.get(copy);
                binaryFrames.add(copy);
                responseLatch.countDown();
                return null;
            }
            if ("toString".equals(name)) {
                return "FakeSession";
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == boolean.class) {
                return false;
            }
            if (returnType == int.class) {
                return 0;
            }
            if (returnType == long.class) {
                return 0L;
            }
            return null;
        }
    }

    private static class TestChannel extends AsynchronousSocketChannel {
        private final int maxWriteSize;
        private final CompletableFuture<Void> connectFuture;
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private final CountDownLatch connectLatch = new CountDownLatch(1);
        private final CountDownLatch writeLatch = new CountDownLatch(1);
        private volatile boolean open = true;
        private volatile SocketAddress remoteAddress;
        private int writeCount;

        TestChannel(int maxWriteSize, CompletableFuture<Void> connectFuture) {
            super(null);
            this.maxWriteSize = maxWriteSize;
            this.connectFuture = connectFuture;
        }

        synchronized byte[] writtenBytes() {
            return written.toByteArray();
        }

        synchronized int writeCount() {
            return writeCount;
        }

        boolean awaitConnect() throws InterruptedException {
            return connectLatch.await(2, TimeUnit.SECONDS);
        }

        boolean awaitWrite() throws InterruptedException {
            return writeLatch.await(2, TimeUnit.SECONDS);
        }

        @Override
        public Future<Void> connect(SocketAddress remote) {
            remoteAddress = remote;
            connectLatch.countDown();
            return connectFuture;
        }

        @Override
        public <A> void connect(SocketAddress remote, A attachment,
                                CompletionHandler<Void, ? super A> handler) {
            remoteAddress = remote;
            connectLatch.countDown();
            connectFuture.whenComplete((ignored, error) -> {
                if (error == null) {
                    handler.completed(null, attachment);
                } else {
                    handler.failed(error, attachment);
                }
            });
        }

        @Override
        public Future<Integer> write(ByteBuffer src) {
            return CompletableFuture.completedFuture(consume(src));
        }

        private synchronized int consume(ByteBuffer src) {
            int count = Math.min(src.remaining(), maxWriteSize);
            byte[] bytes = new byte[count];
            src.get(bytes);
            written.write(bytes, 0, bytes.length);
            writeCount++;
            writeLatch.countDown();
            return count;
        }

        @Override
        public <A> void write(ByteBuffer src, long timeout, TimeUnit unit, A attachment,
                              CompletionHandler<Integer, ? super A> handler) {
            handler.completed(consume(src), attachment);
        }

        @Override
        public <A> void read(ByteBuffer dst, long timeout, TimeUnit unit, A attachment,
                             CompletionHandler<Integer, ? super A> handler) {
        }

        @Override
        public Future<Integer> read(ByteBuffer dst) {
            return new CompletableFuture<Integer>();
        }

        @Override
        public <A> void read(ByteBuffer[] dsts, int offset, int length, long timeout, TimeUnit unit,
                             A attachment, CompletionHandler<Long, ? super A> handler) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <A> void write(ByteBuffer[] srcs, int offset, int length, long timeout, TimeUnit unit,
                              A attachment, CompletionHandler<Long, ? super A> handler) {
            throw new UnsupportedOperationException();
        }

        @Override
        public AsynchronousSocketChannel bind(SocketAddress local) {
            return this;
        }

        @Override
        public <T> AsynchronousSocketChannel setOption(SocketOption<T> name, T value) {
            return this;
        }

        @Override
        public <T> T getOption(SocketOption<T> name) {
            return null;
        }

        @Override
        public Set<SocketOption<?>> supportedOptions() {
            return Collections.emptySet();
        }

        @Override
        public AsynchronousSocketChannel shutdownInput() {
            return this;
        }

        @Override
        public AsynchronousSocketChannel shutdownOutput() {
            return this;
        }

        @Override
        public SocketAddress getRemoteAddress() {
            return remoteAddress;
        }

        @Override
        public SocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
            connectFuture.cancel(true);
        }
    }
}
