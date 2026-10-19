package com.reajason.javaweb.packer;

import lombok.SneakyThrows;
import com.reajason.javaweb.utils.IOUtils;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2025/9/1
 */
public class Util {

    /**
     * Java 源文件中单个字符串常量的上限：class 文件 CONSTANT_Utf8 使用 modified UTF-8，
     * 长度以字节计且最大 65535。这里按字符数留足余量（非 ASCII 字符最多 3 字节），
     * 避免容器自带的旧版 javac（如 Resin 的 sun.tools.javac）在写常量池时直接抛
     * UTFDataFormatException。
     */
    public static final int JAVA_STRING_LITERAL_CHUNK_SIZE = 16384;

    @SneakyThrows
    public static String loadTemplateFromResource(String resourceName) {
        try (InputStream stream = Util.class.getResourceAsStream(resourceName)) {
            return IOUtils.toString(Objects.requireNonNull(stream), Charset.defaultCharset());
        }
    }

    /**
     * 把字符串转换成 Java 源码表达式。短字符串直接返回字面量；超过
     * {@link #JAVA_STRING_LITERAL_CHUNK_SIZE} 时拆成多个字面量，用
     * {@code StringBuilder} 在运行期拼接。
     * <p>
     * 不能简单写成 {@code "a" + "b"}：编译期常量折叠会把它们合并回一个超长常量，
     * 仍然触发同样的 65535 字节限制。
     */
    public static String toJavaStringLiteral(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= JAVA_STRING_LITERAL_CHUNK_SIZE) {
            StringBuilder literal = new StringBuilder(value.length() + 2);
            literal.append('"');
            appendEscaped(literal, value, 0, value.length());
            return literal.append('"').toString();
        }

        StringBuilder expression = new StringBuilder(value.length() + 64);
        expression.append("new StringBuilder()");
        for (int start = 0; start < value.length(); start += JAVA_STRING_LITERAL_CHUNK_SIZE) {
            int end = Math.min(start + JAVA_STRING_LITERAL_CHUNK_SIZE, value.length());
            expression.append("\n        .append(\"");
            appendEscaped(expression, value, start, end);
            expression.append("\")");
        }
        return expression.append("\n        .toString()").toString();
    }

    private static void appendEscaped(StringBuilder out, String value, int start, int end) {
        for (int i = start; i < end; i++) {
            appendEscaped(out, value.charAt(i));
        }
    }

    /**
     * 单引号字面量表达式，供 Groovy / Aviator 这类支持 {@code '...' + '...'} 的脚本使用。
     * 超长时拆成多个字面量并用 {@code +} 在运行期拼接（这两种解析器都不会把字面量相加折叠回
     * 一个超长常量）。
     */
    public static String toSingleQuotedConcatLiteral(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= JAVA_STRING_LITERAL_CHUNK_SIZE) {
            StringBuilder literal = new StringBuilder(value.length() + 2);
            literal.append('\'');
            appendEscaped(literal, value, 0, value.length());
            return literal.append('\'').toString();
        }

        StringBuilder expression = new StringBuilder(value.length() + 64).append('(');
        for (int start = 0; start < value.length(); start += JAVA_STRING_LITERAL_CHUNK_SIZE) {
            int end = Math.min(start + JAVA_STRING_LITERAL_CHUNK_SIZE, value.length());
            if (start > 0) {
                expression.append(" + ");
            }
            expression.append('\'');
            appendEscaped(expression, value, start, end);
            expression.append('\'');
        }
        return expression.append(')').toString();
    }

    /**
     * XPath 1.0 字面量表达式。超长时拆成多个字面量并用 {@code concat(...)} 在运行期拼接。
     * XPath 字符串没有反斜杠转义，调用方只应传入 base64 这类不含引号的文本。
     */
    public static String toXPathStringLiteral(String value) {
        if (value == null) {
            return "''";
        }
        if (value.length() <= JAVA_STRING_LITERAL_CHUNK_SIZE) {
            return "'" + value + "'";
        }

        StringBuilder expression = new StringBuilder(value.length() + 64).append("concat(");
        for (int start = 0; start < value.length(); start += JAVA_STRING_LITERAL_CHUNK_SIZE) {
            int end = Math.min(start + JAVA_STRING_LITERAL_CHUNK_SIZE, value.length());
            if (start > 0) {
                expression.append(',');
            }
            expression.append('\'').append(value, start, end).append('\'');
        }
        return expression.append(')').toString();
    }

    private static void appendEscaped(StringBuilder out, char ch) {
        switch (ch) {
            case '"':
                out.append("\\\"");
                break;
            case '\'':
                out.append("\\'");
                break;
            case '\\':
                out.append("\\\\");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            case '\t':
                out.append("\\t");
                break;
            default:
                if (ch < 0x20 || ch > 0x7e) {
                    out.append("\\u");
                    out.append(Character.forDigit((ch >> 12) & 0xf, 16));
                    out.append(Character.forDigit((ch >> 8) & 0xf, 16));
                    out.append(Character.forDigit((ch >> 4) & 0xf, 16));
                    out.append(Character.forDigit(ch & 0xf, 16));
                } else {
                    out.append(ch);
                }
        }
    }
}
