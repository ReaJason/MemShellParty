package com.reajason.javaweb.asm;

import org.objectweb.asm.ClassReader;

import java.util.Base64;

/**
 * 从 class 字节或 Base64 文本中解析类名。
 */
public class ClassNameParser {

    public String parseClassNameFromBase64(String classBase64) {
        if (classBase64 == null || classBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("class base64 is empty");
        }
        byte[] bytes = Base64.getDecoder().decode(classBase64.trim());
        return parseClassName(bytes);
    }

    public String parseClassName(byte[] classBytes) {
        if (classBytes == null || classBytes.length == 0) {
            throw new IllegalArgumentException("class bytes are empty");
        }
        return new ClassReader(classBytes).getClassName().replace('/', '.');
    }
}
