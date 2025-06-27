package com.reajason.javaweb.packer;

import lombok.Data;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
@Data
public class ClassPackerConfig {
    private String className;
    private byte[] classBytes;
    private String classBytesBase64Str;
    private boolean byPassJavaModule;
}
