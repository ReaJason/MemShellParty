package com.reajason.javaweb.util;

public class ClassDefiner extends ClassLoader {
    private ClassDefiner() {
    }

    public static Class<?> defineClass(byte[] code) {
        return new ClassDefiner().defineClass(null, code, 0, code.length);
    }
}