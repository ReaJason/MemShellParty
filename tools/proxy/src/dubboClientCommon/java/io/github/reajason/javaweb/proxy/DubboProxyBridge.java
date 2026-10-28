package io.github.reajason.javaweb.proxy;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class DubboProxyBridge implements Closeable {

    private final String listenHost;
    private final int listenPort;
    private final DubboHandler dubboHandler;
    private final Set<Session> sessions = Collections.newSetFromMap(new ConcurrentHashMap<Session, Boolean>());
    private final CountDownLatch stopped = new CountDownLatch(1);
    private final AtomicLong sessionIds = new AtomicLong();

    private volatile ServerSocket serverSocket;
    private volatile boolean closed;
    private boolean started;

    public DubboProxyBridge(String listenHost, int listenPort, DubboHandler dubboHandler) {
        this.listenHost = Objects.requireNonNull(listenHost, "listenHost");
        if (listenPort < 0 || listenPort > 65535) {
            throw new IllegalArgumentException("listenPort must be between 0 and 65535");
        }
        this.listenPort = listenPort;
        this.dubboHandler = Objects.requireNonNull(dubboHandler, "dubboHandler");
    }

    public synchronized void start() throws IOException {
        if (started) {
            throw new IllegalStateException("Dubbo proxy bridge has already been started");
        }
        if (closed) {
            throw new IllegalStateException("Dubbo proxy bridge has already been closed");
        }
        ServerSocket server = new ServerSocket();
        try {
            server.bind(new InetSocketAddress(listenHost, listenPort));
        } catch (IOException e) {
            try {
                server.close();
            } catch (IOException ignored) {
            }
            throw e;
        }
        serverSocket = server;
        started = true;
        Thread acceptThread = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "dubbo-proxy-accept-" + server.getLocalPort());
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public int getLocalPort() {
        ServerSocket server = serverSocket;
        if (server == null) {
            throw new IllegalStateException("Dubbo proxy bridge has not been started");
        }
        return server.getLocalPort();
    }

    public void await() throws InterruptedException {
        synchronized (this) {
            if (!started) {
                throw new IllegalStateException("Dubbo proxy bridge has not been started");
            }
        }
        stopped.await();
    }

    private void acceptLoop() {
        try {
            ServerSocket server = serverSocket;
            while (!closed) {
                Socket socket = server.accept();
                Session session = new Session(socket, sessionIds.incrementAndGet());
                sessions.add(session);
                if (closed) {
                    session.close();
                    break;
                }
                session.start();
            }
        } catch (IOException e) {
            if (!closed) {
                System.err.println("Dubbo proxy listener failed: " + e.getMessage());
            }
        } finally {
            close();
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            stopped.countDown();
            return;
        }
        closed = true;
        try {
            ServerSocket server = serverSocket;
            if (server != null) {
                try {
                    server.close();
                } catch (IOException ignored) {
                }
            }
            for (Session session : sessions) {
                session.close();
            }
        } finally {
            stopped.countDown();
        }
    }

    private final class Session implements Closeable {
        private final Socket localSocket;
        private final long id;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean closeSent = new AtomicBoolean();
        private volatile String token;

        Session(Socket localSocket, long id) {
            this.localSocket = localSocket;
            this.id = id;
        }

        void start() {
            Thread sessionThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    runSession();
                }
            }, "dubbo-proxy-session-" + id);
            sessionThread.setDaemon(true);
            sessionThread.start();
        }

        private void runSession() {
            try {
                String createdToken = DubboProxyProtocol.parseCreateResponse(
                        dubboHandler.handle(DubboProxyProtocol.createRequest()));
                token = createdToken;
                if (closed.get()) {
                    closeRemote(createdToken);
                    return;
                }

                final OutputStream localOutput = localSocket.getOutputStream();
                Thread pullThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        runPull(createdToken, localOutput);
                    }
                }, "dubbo-proxy-pull-" + id);
                pullThread.setDaemon(true);
                pullThread.start();
                runPush(createdToken);
                if (closed.get()) {
                    return;
                }
                // 本地 EOF 只关闭上传方向，目标端仍可在收到 EOF 后返回响应。
                DubboProxyProtocol.parseOkResponse(dubboHandler.handle(
                        DubboProxyProtocol.shutdownOutputRequest(createdToken)));
                pullThread.join();
            } catch (Exception e) {
                if (!closed.get()) {
                    System.err.println("Dubbo proxy session " + id + " failed: " + e.getMessage());
                }
            } finally {
                close();
            }
        }

        private void runPush(String sessionToken) throws Exception {
            InputStream localInput = localSocket.getInputStream();
            byte[] buffer = new byte[16384];
            while (!closed.get()) {
                int length = localInput.read(buffer);
                if (length < 0) {
                    return;
                }
                if (length == 0) {
                    continue;
                }
                DubboProxyProtocol.parseOkResponse(dubboHandler.handle(
                        DubboProxyProtocol.pushRequest(sessionToken, buffer, length)));
            }
        }

        private void runPull(String sessionToken, OutputStream localOutput) {
            try {
                while (!closed.get()) {
                    DubboProxyProtocol.PullResponse response = DubboProxyProtocol.parsePullResponse(
                            dubboHandler.handle(DubboProxyProtocol.pullRequest(sessionToken)));
                    if (response.length == -1) {
                        continue;
                    }
                    if (response.length == 0) {
                        return;
                    }
                    localOutput.write(response.payload);
                    localOutput.flush();
                }
            } catch (Exception e) {
                if (!closed.get()) {
                    System.err.println("Dubbo proxy pull " + id + " failed: " + e.getMessage());
                }
            } finally {
                close();
            }
        }

        @Override
        public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            try {
                localSocket.close();
            } catch (IOException ignored) {
            }
            String currentToken = token;
            if (currentToken != null) {
                closeRemote(currentToken);
            }
            sessions.remove(this);
        }

        private void closeRemote(String sessionToken) {
            if (!closeSent.compareAndSet(false, true)) {
                return;
            }
            try {
                DubboProxyProtocol.parseOkResponse(dubboHandler.handle(
                        DubboProxyProtocol.closeRequest(sessionToken)));
            } catch (Exception ignored) {
                // The remote endpoint may already have closed the tunnel.
            }
        }
    }
}
