package com.reajason.javaweb.utils;

/**
 * 字符串空值判断，语义与 {@code org.apache.commons.lang3.StringUtils} 保持一致。
 * <p>
 * 项目原先通过 {@code commons-lang3} 传递依赖使用这些方法，为去掉该依赖，
 * 这里只保留仓库内实际用到的部分。
 *
 * @author ReaJason
 */
public class StringUtils {

    private StringUtils() {
    }

    /**
     * 空白串（含 {@code null}）返回 {@code true}
     */
    public static boolean isBlank(String str) {
        if (str == null) {
            return true;
        }
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static boolean isNotBlank(String str) {
        return !isBlank(str);
    }

    /**
     * 空串（含 {@code null}）返回 {@code true}，与 {@link #isBlank(String)} 的区别是不把空白串当空
     */
    public static boolean isEmpty(String str) {
        return str == null || str.length() == 0;
    }

    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * 任意一个为空串（含 {@code null}）返回 {@code false}，全部非空返回 {@code true}
     */
    public static boolean isNoneEmpty(CharSequence... values) {
        if (values == null) {
            return false;
        }
        for (CharSequence value : values) {
            if (value == null || value.length() == 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isNoneBlank(CharSequence... values) {
        if (values == null) {
            return false;
        }
        for (CharSequence value : values) {
            if (value == null || isBlank(value.toString())) {
                return false;
            }
        }
        return true;
    }

    public static boolean equals(CharSequence cs1, CharSequence cs2) {
        return cs1 == null ? cs2 == null : cs1.equals(cs2);
    }

    /**
     * 任一候选值与目标串相等即返回 {@code true}
     */
    public static boolean equalsAny(CharSequence string, CharSequence... searchStrings) {
        if (searchStrings == null) {
            return false;
        }
        for (CharSequence searchString : searchStrings) {
            if (equals(string, searchString)) {
                return true;
            }
        }
        return false;
    }
}
