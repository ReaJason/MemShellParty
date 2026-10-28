package com.reajason.javaweb.desktop.memshell.service;

/** 桌面 SDK 兼容入口；实现由 common 与 Web 共用。 */
public final class ClassBytesEncoder {

    private ClassBytesEncoder() {
    }

    public static String encode(byte[] classBytes, boolean gzipBase64) {
        return com.reajason.javaweb.bytecode.ClassBytesEncoder.encode(classBytes, gzipBase64);
    }

    public static byte[] gzip(byte[] bytes) {
        return com.reajason.javaweb.bytecode.ClassBytesEncoder.gzip(bytes);
    }
}
