package com.reajason.javaweb.behinder;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class Utils {

    public static final Set<String> JAVA_KEYWORDS = new HashSet<>(Arrays.asList(new String[]{
            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
            "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
            "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
            "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super",
            "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while"
    }));

    public static String getRandomAlpha(int length) {
        String randomString = getRandomStringInternal(length);
        while (JAVA_KEYWORDS.contains(randomString)) {
            randomString = getRandomStringInternal(length);
        }
        return randomString;
    }

    private static String getRandomStringInternal(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(52);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static String getRandomClassName() {
        String[] domainAs = new String[]{"com", "net", "org", "sun"};
        String domainB = getRandomAlpha(5);
        String domainC = getRandomAlpha(5);
        String className = getRandomAlpha(7);
        className = className.substring(0, 1).toUpperCase() + className.substring(1).toLowerCase();
        String domainA = domainAs[(new Random()).nextInt(4)];
        int randomSegments = (new Random()).nextInt(3) + 3;
        if (randomSegments == 3) {
            return domainA + "." + domainB + "." + className;
        } else if (randomSegments == 4) {
            return domainA + "." + domainB + "." + domainC + "." + className;
        } else {
            return domainA + "." + domainB + "." + domainC + "." + className;
        }
    }
}
