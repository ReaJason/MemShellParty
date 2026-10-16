package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.MemShellResult;
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

    public static ClassPackerConfig of(String className, byte[] classBytes, String classBytesBase64Str, boolean byPassJavaModule) {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName(className);
        config.setClassBytes(classBytes);
        config.setClassBytesBase64Str(classBytesBase64Str);
        config.setByPassJavaModule(byPassJavaModule);
        return config;
    }

    public static ClassPackerConfig from(MemShellResult result) {
        return of(result.getInjectorClassName(), result.getInjectorBytes(), result.getInjectorBytesBase64Str(),
                result.getShellConfig() != null && result.getShellConfig().needByPassJavaModule());
    }
}
