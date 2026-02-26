package com.reajason.javaweb.desktop.memshell.service;

import net.bytebuddy.jar.asm.ClassReader;

import java.util.Base64;

public class CustomClassNameParser {
    public String parseClassNameFromBase64(String classBase64) {
        if (classBase64 == null || classBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("class base64 is empty");
        }
        byte[] bytes = Base64.getDecoder().decode(classBase64);
        return parseClassName(bytes);
    }

    public String parseClassName(byte[] classBytes) {
        if (classBytes == null || classBytes.length == 0) {
            throw new IllegalArgumentException("class bytes are empty");
        }
        return new ClassReader(classBytes).getClassName().replace('/', '.');
    }
}
