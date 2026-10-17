package com.reajason.javaweb.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * 基于词表的类名采样器。
 * <p>
 * 生成的类名形如 {@code packageWord.PrefixMiddle<Suffix>}，例如
 * {@code session.SessionValidationFilter}。三个词都从同一个语义域中抽取，
 * 避免出现 {@code http.client.calendar} 这种包名与类名各说各话的组合。
 * <p>
 * 语义域之外的 {@code generic} 域是通用词（如 {@code Default}/{@code Support}），
 * 可以与任意域搭配，用来放大组合空间，同时保持命名自然。
 * <p>
 * 约束：前缀与中段不能相同；中段不能等于后缀（避免 {@code AuthFilterFilter}）；
 * 前缀不能等于后缀；结果必须是合法 Java 标识符且长度受限。
 * <p>
 * 随机源为 {@link RandomUtils} 的静态 {@link java.security.SecureRandom}，不依赖时间戳，
 * 也不需要跨进程的唯一性状态。
 *
 * @author ReaJason
 */
public final class NameSampler {

    private static final int MAX_ATTEMPTS = 128;
    private static final int MAX_SIMPLE_NAME_LENGTH = 64;
    private static final String GENERIC_DOMAIN = "generic";
    private static final String RESOURCE_DIR = "/com/reajason/javaweb/naming/";
    private static final String PACKAGE_WORDS_RESOURCE = RESOURCE_DIR + "package-words.txt";
    private static final String CLASS_PREFIXES_RESOURCE = RESOURCE_DIR + "class-prefixes.txt";
    private static final String CLASS_MIDDLES_RESOURCE = RESOURCE_DIR + "class-middles.txt";

    private static final Map<String, String[]> PACKAGE_WORDS = loadDomains(PACKAGE_WORDS_RESOURCE, true);
    private static final Map<String, String[]> CLASS_PREFIXES = loadDomains(CLASS_PREFIXES_RESOURCE, false);
    private static final Map<String, String[]> CLASS_MIDDLES = loadDomains(CLASS_MIDDLES_RESOURCE, false);

    static {
        checkDomainAlignment();
    }

    private static final String[] PACKAGE_DOMAINS = PACKAGE_WORDS.keySet().toArray(new String[0]);
    private static final String[] ALL_PACKAGE_WORDS = flatten(PACKAGE_WORDS);
    private static final Map<String, String[]> PREFIX_POOLS = buildPools(CLASS_PREFIXES);
    private static final Map<String, String[]> MIDDLE_POOLS = buildPools(CLASS_MIDDLES);
    private static final int MIN_AFFIX_LENGTH = computeMinAffixLength();

    private NameSampler() {
    }

    /**
     * 采样一个类名。
     *
     * @param suffix 自然类名后缀，例如 {@code Filter}、{@code Valve}、{@code Interceptor}
     */
    public static SampledName sample(String suffix) {
        validateSuffix(suffix);
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            String domain = pick(PACKAGE_DOMAINS);
            String packageWord = pick(PACKAGE_WORDS.get(domain));
            String prefix = pick(PREFIX_POOLS.get(domain));
            String middle = pick(MIDDLE_POOLS.get(domain));
            if (isAcceptable(packageWord, prefix, middle, suffix)) {
                return new SampledName(domain, packageWord, prefix + middle + suffix);
            }
        }
        return fallback(suffix);
    }

    /**
     * 采样一个类名并直接返回 {@code packageWord.SimpleName} 形式。
     */
    public static String sampleClassName(String suffix) {
        return sample(suffix).getClassName();
    }

    /**
     * 采样一个词表单词，全小写。用于请求参数名等对外可见的名字。
     */
    public static String sampleWord() {
        return pick(ALL_PACKAGE_WORDS);
    }

    /**
     * 采样一个长度不超过 {@code maxLength} 的词表单词，全小写。
     * 用于需要控制最终类名长度的场景（例如 Shiro Cookie 体积预算）。
     */
    public static String sampleWord(int maxLength) {
        if (maxLength < 1) {
            throw new IllegalArgumentException("maxLength must be positive: " + maxLength);
        }
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            String word = pick(ALL_PACKAGE_WORDS);
            if (word.length() <= maxLength) {
                return word;
            }
        }
        for (String word : ALL_PACKAGE_WORDS) {
            if (word.length() <= maxLength) {
                return word;
            }
        }
        throw new IllegalArgumentException("no word shorter than " + maxLength);
    }

    /**
     * 采样一个包名段，全小写。
     */
    public static String samplePackageSegment() {
        return sampleWord();
    }

    private static SampledName fallback(String suffix) {
        for (String domain : PACKAGE_DOMAINS) {
            for (String packageWord : PACKAGE_WORDS.get(domain)) {
                for (String prefix : PREFIX_POOLS.get(domain)) {
                    for (String middle : MIDDLE_POOLS.get(domain)) {
                        if (isAcceptable(packageWord, prefix, middle, suffix)) {
                            return new SampledName(domain, packageWord, prefix + middle + suffix);
                        }
                    }
                }
            }
        }
        throw new IllegalArgumentException("no valid class name combination for suffix: " + suffix);
    }

    private static int computeMinAffixLength() {
        int minPrefix = Integer.MAX_VALUE;
        for (String prefix : flatten(PREFIX_POOLS)) {
            minPrefix = Math.min(minPrefix, prefix.length());
        }
        int minMiddle = Integer.MAX_VALUE;
        for (String middle : flatten(MIDDLE_POOLS)) {
            minMiddle = Math.min(minMiddle, middle.length());
        }
        if (minPrefix == Integer.MAX_VALUE || minMiddle == Integer.MAX_VALUE) {
            return 0;
        }
        return minPrefix + minMiddle;
    }

    private static boolean isAcceptable(String packageWord, String prefix, String middle, String suffix) {
        if (!isIdentifier(packageWord) || !isIdentifier(prefix) || !isIdentifier(middle)) {
            return false;
        }
        if (CommonUtil.JAVA_KEYWORDS.contains(packageWord)
                || CommonUtil.JAVA_KEYWORDS.contains(prefix)
                || CommonUtil.JAVA_KEYWORDS.contains(middle)) {
            return false;
        }
        if (prefix.equalsIgnoreCase(middle)
                || prefix.equalsIgnoreCase(suffix)
                || middle.equalsIgnoreCase(suffix)) {
            return false;
        }
        // 避免 StandardContext + ContextValve 这类边界重复：ContextContextValve
        if (suffix.startsWith(prefix) || suffix.endsWith(prefix)
                || suffix.startsWith(middle) || suffix.endsWith(middle)) {
            return false;
        }
        return prefix.length() + middle.length() + suffix.length() <= MAX_SIMPLE_NAME_LENGTH;
    }

    private static boolean isIdentifier(String value) {
        if (value.isEmpty() || !Character.isJavaIdentifierStart(value.charAt(0))) {
            return false;
        }
        for (int i = 1; i < value.length(); i++) {
            if (!Character.isJavaIdentifierPart(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static void validateSuffix(String suffix) {
        if (suffix == null || !suffix.matches("[A-Z][A-Za-z0-9]*")) {
            throw new IllegalArgumentException("suffix is not a valid class name suffix: " + suffix);
        }
        int maxSuffixLength = MAX_SIMPLE_NAME_LENGTH - MIN_AFFIX_LENGTH;
        if (suffix.length() > maxSuffixLength) {
            // 长度已经不可能拼出合法类名；提前失败，避免 fallback 全量扫描空转
            throw new IllegalArgumentException("suffix is too long (max " + maxSuffixLength + "): " + suffix);
        }
    }

    /**
     * 判断后缀是否能被采样器接受（合法 PascalCase 且长度在可组合范围内）。
     */
    public static boolean isValidSuffix(String suffix) {
        try {
            validateSuffix(suffix);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String pick(String[] words) {
        return words[RandomUtils.nextInt(words.length)];
    }

    /**
     * 每个语义域的前缀/中段词池 = 本域词 + generic 词。
     * generic 包名段只与 generic 词搭配，类名保持中性。
     */
    private static Map<String, String[]> buildPools(Map<String, String[]> byDomain) {
        String[] generic = byDomain.get(GENERIC_DOMAIN);
        Map<String, String[]> pools = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> entry : byDomain.entrySet()) {
            if (generic == null || GENERIC_DOMAIN.equals(entry.getKey())) {
                pools.put(entry.getKey(), entry.getValue());
            } else {
                pools.put(entry.getKey(), concat(entry.getValue(), generic));
            }
        }
        return pools;
    }

    private static String[] concat(String[] first, String[] second) {
        String[] result = new String[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static String[] flatten(Map<String, String[]> byDomain) {
        Set<String> words = new LinkedHashSet<>();
        for (String[] domainWords : byDomain.values()) {
            for (String word : domainWords) {
                words.add(word);
            }
        }
        return new ArrayList<>(words).toArray(new String[0]);
    }

    /**
     * 三个词表必须使用完全相同的语义域集合，防止新增域时漏写某个角色。
     */
    private static void checkDomainAlignment() {
        if (!PACKAGE_WORDS.keySet().equals(CLASS_PREFIXES.keySet())
                || !PACKAGE_WORDS.keySet().equals(CLASS_MIDDLES.keySet())) {
            throw new IllegalStateException("name resources use different semantic domains: "
                    + PACKAGE_WORDS.keySet() + " / " + CLASS_PREFIXES.keySet()
                    + " / " + CLASS_MIDDLES.keySet());
        }
    }

    private static Map<String, String[]> loadDomains(String resource, boolean lowerCase) {
        InputStream inputStream = NameSampler.class.getResourceAsStream(resource);
        if (inputStream == null) {
            throw new IllegalStateException("missing name resource: " + resource);
        }
        Map<String, Set<String>> domains = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    throw new IllegalStateException("invalid line in " + resource + ": " + line);
                }
                String domain = line.substring(0, colon).trim();
                validateDomain(domain, resource);
                Set<String> words = domains.computeIfAbsent(domain, key -> new LinkedHashSet<>());
                for (String raw : line.substring(colon + 1).split(",")) {
                    String word = raw.trim();
                    if (word.isEmpty()) {
                        continue;
                    }
                    validateWord(word, resource, lowerCase);
                    words.add(word);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to read name resource: " + resource, e);
        }
        if (domains.isEmpty()) {
            throw new IllegalStateException("empty name resource: " + resource);
        }
        Map<String, String[]> result = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> entry : domains.entrySet()) {
            if (entry.getValue().isEmpty()) {
                throw new IllegalStateException(
                        "empty domain in " + resource + ": " + entry.getKey());
            }
            result.put(entry.getKey(), entry.getValue().toArray(new String[0]));
        }
        return result;
    }

    private static void validateDomain(String domain, String resource) {
        if (!domain.matches("[a-z][a-z0-9]*")) {
            throw new IllegalStateException("invalid domain in " + resource + ": " + domain);
        }
    }

    private static void validateWord(String word, String resource, boolean lowerCase) {
        boolean valid = lowerCase
                ? word.matches("[a-z][a-z0-9]*")
                : word.matches("[A-Z][A-Za-z0-9]*");
        if (!valid) {
            throw new IllegalStateException("invalid word in " + resource + ": " + word);
        }
        if (CommonUtil.JAVA_KEYWORDS.contains(word)) {
            throw new IllegalStateException("java keyword in " + resource + ": " + word);
        }
    }

    /**
     * 一次采样结果：包名段与类简单名分开返回，便于调用方拼接到目标中间件的包路径下。
     */
    public static final class SampledName {
        private final String domain;
        private final String packageSegment;
        private final String simpleName;

        private SampledName(String domain, String packageSegment, String simpleName) {
            this.domain = domain;
            this.packageSegment = packageSegment;
            this.simpleName = simpleName;
        }

        String getDomain() {
            return domain;
        }

        public String getPackageSegment() {
            return packageSegment;
        }

        public String getSimpleName() {
            return simpleName;
        }

        public String getClassName() {
            return packageSegment + "." + simpleName;
        }
    }
}
