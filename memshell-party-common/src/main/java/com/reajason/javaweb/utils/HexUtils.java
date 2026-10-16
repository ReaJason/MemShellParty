package com.reajason.javaweb.utils;

/**
 * 十六进制编解码，语义与 {@code org.apache.commons.codec.binary.Hex} 对齐。
 * <p>
 * 项目原先通过 {@code commons-codec} 传递依赖使用这些方法，为去掉该依赖，
 * 这里只保留仓库内实际用到的部分。
 *
 * @author ReaJason
 */
public class HexUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HexUtils() {
    }

    /**
     * 按字节转小写十六进制字符串，每个字节两位，字符集固定为 US-ASCII
     */
    public static String encodeHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            chars[i * 2] = HEX[b >>> 4];
            chars[i * 2 + 1] = HEX[b & 0x0F];
        }
        return new String(chars);
    }

    /**
     * 十六进制字符串转字节数组，入参为 {@code null} 时返回 {@code null}
     */
    public static byte[] decodeHex(String str) {
        if (str == null) {
            return null;
        }
        int length = str.length();
        if ((length & 1) != 0) {
            throw new IllegalArgumentException("Odd number of characters: " + str);
        }
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            int high = toDigit(str.charAt(i), i);
            int low = toDigit(str.charAt(i + 1), i + 1);
            bytes[i / 2] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    private static int toDigit(char ch, int index) {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new IllegalArgumentException("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }
}
