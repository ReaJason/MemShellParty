package com.reajason.javaweb.godzilla;

import lombok.SneakyThrows;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class BlockingJavaWebSocketClient extends WebSocketClient {

    private CountDownLatch connectLatch = new CountDownLatch(1);
    private volatile CountDownLatch responseLatch;
    private final AtomicReference<String> responseMessage = new AtomicReference<>();
    private final AtomicReference<byte[]> responseBytesMessage = new AtomicReference<>();
    private volatile boolean connected = false;

    public BlockingJavaWebSocketClient(URI serverUri) {
        super(serverUri);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
        System.out.println("连接成功");
        connected = true;
        connectLatch.countDown();
    }

    public void onMessage(String message) {
        System.out.println("收到消息: " + message);
        responseMessage.set(message);
        if (responseLatch != null) {
            responseLatch.countDown();
        }
        close();
    }

    public void onMessage(ByteBuffer byteBuffer) {
        System.out.println("收到字节消息: " + byteBuffer);
        responseBytesMessage.set(byteBuffer.array());
        if (responseLatch != null) {
            responseLatch.countDown();
        }
        close();
    }

    public void onClose(int code, String reason, boolean remote) {
        System.out.println("连接关闭: " + code + " - " + reason);
        connected = false;
        // Signal any waiting threads
        if (responseLatch != null) {
            responseLatch.countDown();
        }
        connectLatch.countDown();
    }

    public void onError(Exception ex) {
        System.out.println("连接错误: " + ex.getMessage());
        connected = false;
        // Signal any waiting threads
        if (responseLatch != null) {
            responseLatch.countDown();
        }
        connectLatch.countDown();
        ex.printStackTrace();
    }

    public String sendRequest(String message) throws InterruptedException {
        // Connect if not already connected
        if (!connected && !isOpen()) {
            connect();
            if (!connectLatch.await(5, TimeUnit.SECONDS)) {
                throw new InterruptedException("Timeout during WebSocket connection.");
            }
        }

        if (!connected || !isOpen()) {
            throw new IllegalStateException("WebSocket connection is not open.");
        }

        // Reset response data and create new response latch for this request
        responseMessage.set(null);
        responseBytesMessage.set(null);
        responseLatch = new CountDownLatch(1);

        // Send the message
        send(message);

        // Wait for response
        if (!responseLatch.await(10, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout waiting for WebSocket response.");
        }

        // Check if connection was closed during wait
        if (!connected) {
            throw new IllegalStateException("WebSocket connection was closed while waiting for response.");
        }

        return responseMessage.get();
    }

    public byte[] sendRequest(ByteBuffer message) throws InterruptedException {
        // Connect if not already connected
        if (!connected && !isOpen()) {
            connect();
            if (!connectLatch.await(5, TimeUnit.SECONDS)) {
                throw new InterruptedException("Timeout during WebSocket connection.");
            }
        }

        if (!connected || !isOpen()) {
            throw new IllegalStateException("WebSocket connection is not open.");
        }

        // Reset response data and create new response latch for this request
        responseMessage.set(null);
        responseBytesMessage.set(null);
        responseLatch = new CountDownLatch(1);

        // Send the message
        send(message);

        // Wait for response
        if (!responseLatch.await(10, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout waiting for WebSocket response.");
        }

        // Check if connection was closed during wait
        if (!connected) {
            throw new IllegalStateException("WebSocket connection was closed while waiting for response.");
        }

        return responseBytesMessage.get();
    }

    public void disconnect() {
        if (connected && isOpen()) {
            close();
        }
    }


    @SneakyThrows
    public static String sendRequestWaitResponse(String entrypoint, String message) {
        BlockingJavaWebSocketClient blockingJavaWebSocketClient = new BlockingJavaWebSocketClient(URI.create(entrypoint));
        return blockingJavaWebSocketClient.sendRequest(message);
    }

    @SneakyThrows
    public static byte[] sendRequestWaitResponse(String entrypoint, ByteBuffer message) {
        BlockingJavaWebSocketClient blockingJavaWebSocketClient = new BlockingJavaWebSocketClient(URI.create(entrypoint));
        return blockingJavaWebSocketClient.sendRequest(message);
    }

    public static void main(String[] args) {
        String uri = "ws://localhost:8082/app/fuck";
        System.out.println("Response 1: " + BlockingJavaWebSocketClient.sendRequestWaitResponse(uri, "id"));
        System.out.println("Response 2: " + BlockingJavaWebSocketClient.sendRequestWaitResponse(uri, "whoami"));
    }
}