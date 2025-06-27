package com.reajason.javaweb.packer;

import lombok.Data;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
@Data
public class JarPackerConfig {
    private String mainClassName;
    private transient Map<String, byte[]> classBytes;
}
