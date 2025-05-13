package com.reajason.javaweb.godzilla;

import lombok.SneakyThrows;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class BlockingJavaWebSocketClient extends WebSocketClient {

    private CountDownLatch connectLatch = new CountDownLatch(1);
    private CountDownLatch responseLatch = new CountDownLatch(1);
    private final AtomicReference<String> responseMessage = new AtomicReference<>();
    private final AtomicReference<byte[]> responseBytesMessage = new AtomicReference<>();
    private volatile boolean connected = false;

    public BlockingJavaWebSocketClient(URI serverUri) {
        super(serverUri);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
        connected = true;
        connectLatch.countDown();
    }

    @Override
    public void onMessage(String message) {
        responseMessage.set(message);
        responseLatch.countDown();
        close();
    }

    @Override
    public void onMessage(ByteBuffer byteBuffer) {
        responseBytesMessage.set(byteBuffer.array());
        responseLatch.countDown();
        close();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        responseLatch.countDown();
        connectLatch.countDown();
        connected = false;
    }

    @Override
    public void onError(Exception ex) {
        responseLatch.countDown();
        connectLatch.countDown();
        connected = false;
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

    public String sendRequest(String message) throws InterruptedException {
        connect();
        if (!connectLatch.await(5, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout during WebSocket connection.");
        }
        if (!connected) {
            throw new IllegalStateException("WebSocket connection is not open.");
        }

        responseMessage.set(null);
        connectLatch = new CountDownLatch(1);
        responseLatch = new CountDownLatch(1);
        send(message);

        if (!responseLatch.await(5, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout waiting for WebSocket response.");
        }
        return responseMessage.get();
    }

    public byte[] sendRequest(ByteBuffer message) throws InterruptedException {
        connect();
        if (!connectLatch.await(5, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout during WebSocket connection.");
        }
        if (!connected) {
            throw new IllegalStateException("WebSocket connection is not open.");
        }

        responseBytesMessage.set(null);
        connectLatch = new CountDownLatch(1);
        responseLatch = new CountDownLatch(1);
        send(message);

        if (!responseLatch.await(5, TimeUnit.SECONDS)) {
            throw new InterruptedException("Timeout waiting for WebSocket response.");
        }
        return responseBytesMessage.get();
    }

    public static void main(String[] args) {
        String uri = "ws://localhost:8082/app/fuck";
        System.out.println("Response 1: " + BlockingJavaWebSocketClient.sendRequestWaitResponse(uri, "id"));
        System.out.println("Response 2: " + BlockingJavaWebSocketClient.sendRequestWaitResponse(uri, "whoami"));
    }
}