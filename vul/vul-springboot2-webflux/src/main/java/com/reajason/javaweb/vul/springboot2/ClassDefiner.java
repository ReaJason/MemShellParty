package com.reajason.javaweb.vul.springboot2;

public class ClassDefiner extends ClassLoader {
    public ClassDefiner() {
    }

    public ClassDefiner(ClassLoader parent) {
        super(parent);
    }

    public Class<?> defineClass(byte[] bytes) {
        return defineClass(null, bytes, 0, bytes.length);
    }
}