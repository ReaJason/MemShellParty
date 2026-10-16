package com.reajason.javaweb.utils;

import java.security.SecureRandom;

/**
 * 随机串生成，语义与 {@code org.apache.commons.lang3.RandomStringUtils} 对齐。
 * <p>
 * 项目原先通过 {@code commons-lang3} 传递依赖使用这些方法，为去掉该依赖，这里基于
 * {@link SecureRandom} 重新实现：生成的标识会出现在内存马类名、URL 路由等处，
 * 可预测性会降低隐蔽性，因此不使用 {@link java.util.Random}。
 *
 * @author ReaJason
 */
public class RandomUtils {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    private RandomUtils() {
    }

    /**
     * 生成指定长度的随机大小写字母串
     */
    public static String randomAlphabetic(int count) {
        return random(count, ALPHABET);
    }

    /**
     * 生成指定长度的随机小写字母串
     */
    public static String randomAlphabeticLowerCase(int count) {
        return random(count, "abcdefghijklmnopqrstuvwxyz".toCharArray());
    }

    private static String random(int count, char[] alphabet) {
        if (count < 0) {
            throw new IllegalArgumentException("count must not be negative: " + count);
        }
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(alphabet[RANDOM.nextInt(alphabet.length)]);
        }
        return sb.toString();
    }
}
