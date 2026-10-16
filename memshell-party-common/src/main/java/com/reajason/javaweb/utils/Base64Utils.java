package com.reajason.javaweb.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Base64 编解码，语义与 {@code org.apache.commons.codec.binary.Base64} 对齐。
 * <p>
 * 项目原先通过 {@code commons-codec} 传递依赖使用这些方法，为去掉该依赖，
 * 这里转发到 JDK 自带的 {@link java.util.Base64}。注意 commons-codec 与 JDK 的差异：
 * <ul>
 *   <li>编码结果一律补齐 {@code =}，等价于 {@code Base64.encodeBase64String}</li>
 *   <li>解码按 MIME 解码器处理，输入中的换行、空白会被忽略，非法字符抛 {@link IllegalArgumentException}</li>
 * </ul>
 *
 * @author ReaJason
 */
public class Base64Utils {

    private Base64Utils() {
    }

    public static byte[] encodeBase64(byte[] bytes) {
        return bytes == null ? null : Base64.getEncoder().encode(bytes);
    }

    public static String encodeBase64String(byte[] bytes) {
        return bytes == null ? null : Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 解码 Base64 字符串，兼容带换行、缩进的输入；入参为 {@code null} 时返回 {@code null}
     */
    public static byte[] decodeBase64(String str) {
        return str == null ? null : decodeBase64(str.getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * 解码 Base64 字节数组，兼容带换行、缩进的输入；入参为 {@code null} 时返回 {@code null}
     */
    public static byte[] decodeBase64(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Base64.getMimeDecoder().decode(bytes);
    }
}
