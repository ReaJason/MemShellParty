package io.github.reajason.javaweb.proxy;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DubboProxyBridgeTest {

    private static final String CONNECT_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n";

    @Test
    void forwardsConnectAndPayloadsForIndependentSessions() throws Exception {
        try (ConnectEchoServer target = new ConnectEchoServer();
             FakeDubboHandler dubboHandler = new FakeDubboHandler(target.getLocalPort());
             DubboProxyBridge bridge = new DubboProxyBridge("127.0.0.1", 0, dubboHandler)) {
            bridge.start();

            try (Socket first = new Socket("127.0.0.1", bridge.getLocalPort());
                 Socket second = new Socket("127.0.0.1", bridge.getLocalPort())) {
                first.setSoTimeout(5000);
                second.setSoTimeout(5000);

                String firstConnect = "CONNECT example.test:443 HTTP/1.1\r\n\r\n";
                String secondConnect = "CONNECT 127.0.0.1:8080 HTTP/1.1\r\n\r\n";
                writeAscii(first, firstConnect);
                writeAscii(second, secondConnect);
                assertEquals(CONNECT_RESPONSE, readHeader(first.getInputStream()));
                assertEquals(CONNECT_RESPONSE, readHeader(second.getInputStream()));

                byte[] firstPayload = new byte[]{0, 1, 2, 10, 13, 127, (byte) 255};
                byte[] secondPayload = "second-session-payload".getBytes(StandardCharsets.UTF_8);
                first.getOutputStream().write(firstPayload);
                first.getOutputStream().flush();
                second.getOutputStream().write(secondPayload);
                second.getOutputStream().flush();
                assertArrayEquals(firstPayload, readFully(first, firstPayload.length));
                assertArrayEquals(secondPayload, readFully(second, secondPayload.length));

                byte[] firstFollowUp = "first-after-connect".getBytes(StandardCharsets.UTF_8);
                byte[] secondFollowUp = "second-after-connect".getBytes(StandardCharsets.UTF_8);
                first.getOutputStream().write(firstFollowUp);
                first.getOutputStream().flush();
                second.getOutputStream().write(secondFollowUp);
                second.getOutputStream().flush();
                assertArrayEquals(firstFollowUp, readFully(first, firstFollowUp.length));
                assertArrayEquals(secondFollowUp, readFully(second, secondFollowUp.length));

                assertEquals(2, dubboHandler.createdTokens.size());
                assertNotEquals(dubboHandler.createdTokens.get(0), dubboHandler.createdTokens.get(1));
                assertTrue(target.connectHeaders.contains(firstConnect));
                assertTrue(target.connectHeaders.contains(secondConnect));
            }

            awaitRemoteClose(dubboHandler, 2);
        }
    }

    @Test
    void forwardsHalfCloseAndDeliversResponseAfterUploadEof() throws Exception {
        final byte[] upload = "upload-body".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] response = "response-after-upload-eof".getBytes(StandardCharsets.ISO_8859_1);
        try (ServerSocket target = new ServerSocket(0);
             FakeDubboHandler dubboHandler = new FakeDubboHandler(target.getLocalPort());
             DubboProxyBridge bridge = new DubboProxyBridge("127.0.0.1", 0, dubboHandler)) {
            Thread targetWorker = new Thread(new Runnable() {
                @Override
                public void run() {
                    try (Socket socket = target.accept()) {
                        InputStream input = socket.getInputStream();
                        ByteArrayOutputStream received = new ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int length;
                        while ((length = input.read(buffer)) >= 0) {
                            if (length > 0) {
                                received.write(buffer, 0, length);
                            }
                        }
                        if (!Arrays.equals(upload, received.toByteArray())) {
                            throw new IOException("Target received a different upload");
                        }
                        socket.getOutputStream().write(response);
                        socket.getOutputStream().flush();
                    } catch (IOException ignored) {
                    }
                }
            }, "dubbo-proxy-half-close-target");
            targetWorker.setDaemon(true);
            targetWorker.start();
            bridge.start();

            try (Socket client = new Socket("127.0.0.1", bridge.getLocalPort())) {
                client.setSoTimeout(5000);
                client.getOutputStream().write(upload);
                client.getOutputStream().flush();
                client.shutdownOutput();

                assertArrayEquals(response, readFully(client, response.length));
                assertEquals(-1, client.getInputStream().read());
            }

            targetWorker.join(5000);
            assertFalse(targetWorker.isAlive(), "target must finish after receiving the upload EOF");
            awaitRemoteClose(dubboHandler, 1);
        }
    }

    private static void awaitRemoteClose(FakeDubboHandler handler, int expected) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (handler.sessions.isEmpty() && handler.closeCount.get() == expected) {
                return;
            }
            Thread.sleep(10);
        }
        assertEquals(expected, handler.closeCount.get());
        assertTrue(handler.sessions.isEmpty());
    }

    private static void writeAscii(Socket socket, String value) throws IOException {
        socket.getOutputStream().write(value.getBytes(StandardCharsets.ISO_8859_1));
        socket.getOutputStream().flush();
    }

    private static byte[] readFully(Socket socket, int length) throws IOException {
        byte[] result = new byte[length];
        new DataInputStream(socket.getInputStream()).readFully(result);
        return result;
    }

    private static String readHeader(InputStream input) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (bytes.size() < 8192) {
            int next = input.read();
            if (next < 0) {
                throw new EOFException("Connection closed before HTTP headers completed");
            }
            bytes.write(next);
            byte[] current = bytes.toByteArray();
            int length = current.length;
            if (length >= 4
                    && current[length - 4] == '\r' && current[length - 3] == '\n'
                    && current[length - 2] == '\r' && current[length - 1] == '\n') {
                return new String(current, StandardCharsets.ISO_8859_1);
            }
        }
        throw new IOException("HTTP headers exceed 8192 bytes");
    }

    private static final class FakeDubboHandler implements DubboHandler, Closeable {
        private final int targetPort;
        private final Map<String, FakeSession> sessions = new ConcurrentHashMap<String, FakeSession>();
        private final CopyOnWriteArrayList<String> createdTokens = new CopyOnWriteArrayList<String>();
        private final AtomicInteger sessionIds = new AtomicInteger();
        private final AtomicInteger closeCount = new AtomicInteger();

        FakeDubboHandler(int targetPort) {
            this.targetPort = targetPort;
        }

        @Override
        public byte[] handle(byte[] request) throws Exception {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(request));
            int operation = input.readUnsignedByte();
            switch (operation) {
                case 0:
                    return create();
                case 1:
                    return push(input);
                case 2:
                    return pull(input);
                case 3:
                    return close(input);
                case 4:
                    return shutdownOutput(input);
                default:
                    return error("Unknown operation " + operation);
            }
        }

        private byte[] create() throws IOException {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress("127.0.0.1", targetPort), 5000);
                String token = "fake-session-" + sessionIds.incrementAndGet();
                FakeSession session = new FakeSession(socket);
                sessions.put(token, session);
                createdTokens.add(token);
                session.start();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(bytes);
                output.writeByte(0);
                output.writeUTF(token);
                output.flush();
                return bytes.toByteArray();
            } catch (IOException e) {
                socket.close();
                throw e;
            }
        }

        private byte[] push(DataInputStream input) throws IOException {
            String token = input.readUTF();
            int length = input.readInt();
            if (length < 0) {
                return error("Negative payload length");
            }
            byte[] payload = new byte[length];
            input.readFully(payload);
            FakeSession session = sessions.get(token);
            if (session == null) {
                return error("Unknown session " + token);
            }
            session.push(payload);
            return ok();
        }

        private byte[] pull(DataInputStream input) throws Exception {
            String token = input.readUTF();
            FakeSession session = sessions.get(token);
            if (session == null) {
                return error("Unknown session " + token);
            }
            byte[] payload = session.downstream.poll(25, TimeUnit.MILLISECONDS);
            if (payload == null) {
                return pullResponse(-1, null);
            }
            return pullResponse(payload.length, payload);
        }

        private byte[] close(DataInputStream input) throws IOException {
            String token = input.readUTF();
            FakeSession session = sessions.remove(token);
            if (session == null) {
                return error("Unknown session " + token);
            }
            closeCount.incrementAndGet();
            session.close();
            return ok();
        }

        private byte[] shutdownOutput(DataInputStream input) throws IOException {
            String token = input.readUTF();
            FakeSession session = sessions.get(token);
            if (session == null) {
                return error("Unknown session " + token);
            }
            session.shutdownOutput();
            return ok();
        }

        private static byte[] ok() {
            return new byte[]{0};
        }

        private static byte[] pullResponse(int length, byte[] payload) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeByte(0);
            output.writeInt(length);
            if (length > 0) {
                output.write(payload);
            }
            output.flush();
            return bytes.toByteArray();
        }

        private static byte[] error(String message) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeByte(1);
            output.writeUTF(message);
            output.flush();
            return bytes.toByteArray();
        }

        @Override
        public void close() {
            for (FakeSession session : sessions.values()) {
                session.close();
            }
            sessions.clear();
        }
    }

    private static final class FakeSession implements Closeable {
        private static final byte[] END = new byte[0];

        private final Socket targetSocket;
        private final LinkedBlockingQueue<byte[]> downstream = new LinkedBlockingQueue<byte[]>();
        private final AtomicBoolean closed = new AtomicBoolean();

        FakeSession(Socket targetSocket) {
            this.targetSocket = targetSocket;
        }

        void start() {
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    readTarget();
                }
            }, "fake-dubbo-target-reader");
            reader.setDaemon(true);
            reader.start();
        }

        private void readTarget() {
            try {
                InputStream input = targetSocket.getInputStream();
                byte[] buffer = new byte[4096];
                while (!closed.get()) {
                    int length = input.read(buffer);
                    if (length < 0) {
                        downstream.offer(END);
                        return;
                    }
                    if (length > 0) {
                        byte[] payload = new byte[length];
                        System.arraycopy(buffer, 0, payload, 0, length);
                        downstream.offer(payload);
                    }
                }
            } catch (IOException e) {
                if (!closed.get()) {
                    downstream.offer(END);
                }
            }
        }

        void push(byte[] payload) throws IOException {
            OutputStream output = targetSocket.getOutputStream();
            output.write(payload);
            output.flush();
        }

        void shutdownOutput() throws IOException {
            targetSocket.shutdownOutput();
        }

        @Override
        public void close() {
            closed.set(true);
            try {
                targetSocket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static final class ConnectEchoServer implements Closeable {
        private final ServerSocket serverSocket;
        private final Set<Socket> clients = Collections.newSetFromMap(new ConcurrentHashMap<Socket, Boolean>());
        private final CopyOnWriteArrayList<String> connectHeaders = new CopyOnWriteArrayList<String>();
        private final AtomicBoolean closed = new AtomicBoolean();

        ConnectEchoServer() throws IOException {
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            Thread acceptThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    acceptLoop();
                }
            }, "connect-echo-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        int getLocalPort() {
            return serverSocket.getLocalPort();
        }

        private void acceptLoop() {
            try {
                while (!closed.get()) {
                    final Socket socket = serverSocket.accept();
                    clients.add(socket);
                    Thread worker = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            serve(socket);
                        }
                    }, "connect-echo-session");
                    worker.setDaemon(true);
                    worker.start();
                }
            } catch (IOException ignored) {
            }
        }

        private void serve(Socket socket) {
            try {
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                connectHeaders.add(readHeader(input));
                output.write(CONNECT_RESPONSE.getBytes(StandardCharsets.ISO_8859_1));
                output.flush();

                byte[] buffer = new byte[4096];
                while (!closed.get()) {
                    int length = input.read(buffer);
                    if (length < 0) {
                        return;
                    }
                    if (length > 0) {
                        output.write(buffer, 0, length);
                        output.flush();
                    }
                }
            } catch (IOException ignored) {
            } finally {
                clients.remove(socket);
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }

        @Override
        public void close() {
            closed.set(true);
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
            for (Socket client : clients) {
                try {
                    client.close();
                } catch (IOException ignored) {
                }
            }
        }
    }
}
