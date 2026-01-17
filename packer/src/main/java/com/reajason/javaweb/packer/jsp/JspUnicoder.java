package com.reajason.javaweb.packer.jsp;

import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

public class JspUnicoder {

    public static String encode(String content, boolean isJsp) {
        if (content == null) {
            return null;
        }
        StringBuilder result = new StringBuilder(content.length());
        int lineStart = 0;
        int length = content.length();
        for (int i = 0; i < length; i++) {
            if (content.charAt(i) == '\n') {
                appendEncodedLine(result, content.substring(lineStart, i), isJsp);
                result.append('\n');
                lineStart = i + 1;
            }
        }
        if (lineStart <= length) {
            appendEncodedLine(result, content.substring(lineStart), isJsp);
        }
        return result.toString();
    }

    private static void appendEncodedLine(StringBuilder output, String line, boolean isJsp) {
        if (shouldSkipLine(line, isJsp)) {
            output.append(line);
            return;
        }
        if (line.contains("page import") || line.contains("page pageEncoding") || line.contains("page contentType")) {
            int firstQuote = line.indexOf('"');
            int lastQuote = line.lastIndexOf('"');
            if (firstQuote != -1 && lastQuote > firstQuote) {
                String oldStr = line.substring(firstQuote + 1, lastQuote);
                String encoded = encodeWordChars(oldStr);
                output.append(line, 0, firstQuote + 1)
                        .append(encoded)
                        .append(line.substring(lastQuote));
                return;
            }
        }
        output.append(encodeWordChars(line));
    }

    private static boolean shouldSkipLine(String line, boolean isJsp) {
        if (line == null) {
            return false;
        }
        if (!isJsp && (line.contains("jsp:root")
                || line.contains("jsp:declaration")
                || line.contains("jsp:scriptlet")
                || line.contains("jsp:directive.page"))) {
            return true;
        }
        return false;
    }

    private static String encodeWordChars(String input) {
        StringBuilder encoded = new StringBuilder(input.length() * 4);
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (isWordChar(ch)) {
                encoded.append(toUnicodeEscape(ch));
            } else {
                encoded.append(ch);
            }
        }
        return encoded.toString();
    }

    private static boolean isWordChar(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private static String toUnicodeEscape(char ch) {
        byte[] bytes = String.valueOf(ch).getBytes(StandardCharsets.UTF_8);
        return "\\u00" + Hex.encodeHexString(bytes);
    }
}

