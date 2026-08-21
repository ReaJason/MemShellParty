package com.reajason.javaweb.vul.springboot4;

public class ClassDefiner extends ClassLoader {
    public ClassDefiner() {
    }

    public ClassDefiner(ClassLoader parent) {
        super(parent);
    }

    public Class<?> defineClass(byte[] code) {
        return defineClass(null, code, 0, code.length);
    }
}