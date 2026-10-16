package com.reajason.javaweb.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 摘要工具，语义与 {@code org.apache.commons.codec.digest.DigestUtils} 对齐。
 * <p>
 * 项目原先通过 {@code commons-codec} 传递依赖使用这些方法，为去掉该依赖，
 * 这里基于 JDK {@link MessageDigest} 重新实现。MD5 仅用于内存马与客户端之间的协议兼容，
 * 不用于安全场景。
 *
 * @author ReaJason
 */
public class DigestUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private DigestUtils() {
    }

    /**
     * MD5 摘要，返回 32 位小写十六进制字符串
     */
    public static String md5Hex(String data) {
        if (data == null) {
            return null;
        }
        return hex(digest("MD5", data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * MD5 摘要，返回 16 字节原始结果
     */
    public static byte[] md5(byte[] data) {
        return data == null ? null : digest("MD5", data);
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (NoSuchAlgorithmException e) {
            // JDK 必须提供 MD5，走到这里说明运行环境不完整
            throw new IllegalStateException(algorithm + " not available", e);
        }
    }

    private static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            chars[i * 2] = HEX[b >>> 4];
            chars[i * 2 + 1] = HEX[b & 0x0F];
        }
        return new String(chars);
    }
}
