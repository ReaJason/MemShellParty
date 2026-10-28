package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.MemShellResult;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
@Data
public class JarPackerConfig {
    private String mainClassName;
    private transient Map<String, byte[]> classBytes;

    public static JarPackerConfig from(MemShellResult result) {
        JarPackerConfig config = new JarPackerConfig();
        config.setMainClassName(result.getInjectorClassName());
        Map<String, byte[]> bytes = new HashMap<>();
        bytes.put(result.getShellClassName(), result.getShellBytes());
        bytes.put(result.getInjectorClassName(), result.getInjectorBytes());
        if (result.getInjectorInnerClassBytes() != null) {
            bytes.putAll(result.getInjectorInnerClassBytes());
        }
        config.setClassBytes(bytes);
        return config;
    }

    public static JarPackerConfig from(ClassPackerConfig classConfig) {
        JarPackerConfig config = new JarPackerConfig();
        config.setMainClassName(classConfig.getClassName());
        Map<String, byte[]> bytes = new HashMap<>();
        bytes.put(classConfig.getClassName(), classConfig.getClassBytes());
        config.setClassBytes(bytes);
        return config;
    }
}
