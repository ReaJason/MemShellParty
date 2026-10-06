package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.GenerationException;
import org.springframework.asm.ClassReader;
import org.springframework.cglib.core.ClassNameReader;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * 从 class 字节码解析全限定类名。
 * <p>
 * Custom 内存马工作流的必要一环：生成时需要同时提供 {@code shellClassBase64} 与
 * {@code shellClassName}，而调用方通常只有字节码。
 *
 * @author ReaJason
 */
@Service
public class ClassNameParseService {

    /**
     * @param classBase64 class 字节码的 Base64
     * @return 类名，形如 {@code com.example.MyShell}
     * @throws GenerationException 输入为空、不是合法 Base64，或不是合法的 class 字节码
     */
    public String parse(String classBase64) {
        if (classBase64 == null || classBase64.isBlank()) {
            throw new GenerationException("class bytes must not be blank");
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(classBase64.trim());
        } catch (IllegalArgumentException e) {
            throw new GenerationException("invalid base64 class bytes: " + e.getMessage(), e);
        }
        try {
            return ClassNameReader.getClassName(new ClassReader(bytes));
        } catch (RuntimeException e) {
            throw new GenerationException("malformed class bytes: " + e.getMessage(), e);
        }
    }
}
