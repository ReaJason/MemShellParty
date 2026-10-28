package com.reajason.javaweb.utils;

import lombok.SneakyThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 */
public class CommonUtil {

    public static final Set<String> JAVA_KEYWORDS = new HashSet<>(Arrays.asList("abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
            "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
            "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
            "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super",
            "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while"));
    /**
     * 固定包名前缀只负责“看起来像哪个生态”，唯一性由 {@link NameSampler} 的词表采样承担。
     * <p>
     * 每个前缀都保留 3 段，且整体不是任何已知框架的真实包路径：
     * 避免生成的类正好落进 {@code org.apache.commons}、{@code org.springframework.context}
     * 这类常见包，降低与既有类 FQCN 碰撞的概率。
     * <p>
     * 不要放测试框架包（例如 org.junit）：生产 JVM 里出现会非常突兀。
     */
    private static final String[] PACKAGE_NAMES = {
            "org.springframework.foundation.support",
            "org.apache.platform.runtime",
            "org.apache.commons.foundation.internal",
            "com.fasterxml.jackson.runtime.support",
            "com.google.gson.platform.internal",
            "ch.qos.logback.foundation.runtime",
            "org.slf4j.utils"
    };

    @SneakyThrows
    public static byte[] gzipCompress(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }

    @SneakyThrows
    public static byte[] gzipDecompress(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data))) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = gzip.read(buffer)) != -1) {
                out.write(buffer, 0, length);

            }
        }
        return out.toByteArray();
    }

    public static String getRandomString(int length) {
        String randomString = getRandomStringInternal(length);
        while (JAVA_KEYWORDS.contains(randomString)) {
            randomString = getRandomStringInternal(length);
        }
        return randomString;
    }

    private static String getRandomStringInternal(int length) {
        return RandomUtils.randomAlphabetic(length);
    }

    public static String getPackageName(String className) {
        return className.substring(0, className.lastIndexOf("."));
    }

    public static String generateClassName() {
        NameSampler.SampledName name = NameSampler.sample("Handler");
        return randomPackagePrefix() + "." + name.getPackageSegment() + "." + name.getSimpleName();
    }

    public static String generateInjectorClassName() {
        NameSampler.SampledName name = NameSampler.sample("Utils");
        return randomPackagePrefix() + "." + name.getPackageSegment() + "." + name.getSimpleName();
    }

    public static String generateRandomPackage() {
        NameSampler.SampledName name = NameSampler.sample("Utils");
        return randomPackagePrefix() + "." + name.getPackageSegment();
    }

    private static String randomPackagePrefix() {
        return PACKAGE_NAMES[RandomUtils.nextInt(PACKAGE_NAMES.length)];
    }

    public static String appendLambdaSuffix(String className) {
        if (className.contains("$Lambda$")) {
            return className;
        }
        return className + "$Proxy0$$Lambda$1";
    }

    public static String getSimpleName(String className) {
        return className.substring(className.lastIndexOf(".") + 1);
    }
}
