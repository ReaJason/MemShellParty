package com.reajason.javaweb.probe;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/8/5
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderClassName = "Builder")
public class ProbeShellResult {
    private String shellClassName;
    private transient byte[] shellBytes;
    private long shellSize;
    private String shellBytesBase64Str;
    private ProbeConfig probeConfig;
    private ProbeContentConfig probeContentConfig;

    public static class Builder {
        public ProbeShellResult build() {
            if (shellBytes != null) {
                shellBytesBase64Str = Base64.getEncoder().encodeToString(shellBytes);
                shellSize = shellBytes.length;
            }
            return new ProbeShellResult(shellClassName, shellBytes, shellSize, shellBytesBase64Str, probeConfig, probeContentConfig);
        }
    }

    public ClassPackerConfig toClassPackerConfig() {
        ClassPackerConfig classPackerConfig = new ClassPackerConfig();
        classPackerConfig.setClassName(shellClassName);
        classPackerConfig.setClassBytes(shellBytes);
        classPackerConfig.setClassBytesBase64Str(shellBytesBase64Str);
        if (probeConfig != null) {
            classPackerConfig.setByPassJavaModule(probeConfig.needByPassJavaModule());
        }
        return classPackerConfig;
    }
}
