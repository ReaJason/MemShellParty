package com.reajason.javaweb.antsword;

import java.util.Random;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class Utils {

    public static String getRandomAlpha(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; ++i) {
            int number = random.nextInt(52);
            sb.append(str.charAt(number));
        }

        return sb.toString();
    }

    public static String getRandomClassName() {
        String[] domainAs = new String[]{"com", "net", "org", "sun"};
        String domainB = getRandomAlpha((new Random()).nextInt(5) + 3).toLowerCase();
        String domainC = getRandomAlpha((new Random()).nextInt(5) + 3).toLowerCase();
        String domainD = getRandomAlpha((new Random()).nextInt(5) + 3).toLowerCase();
        String className = getRandomAlpha((new Random()).nextInt(7) + 4);
        className = className.substring(0, 1).toUpperCase() + className.substring(1).toLowerCase();
        int domainAIndex = (new Random()).nextInt(4);
        String domainA = domainAs[domainAIndex];
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
