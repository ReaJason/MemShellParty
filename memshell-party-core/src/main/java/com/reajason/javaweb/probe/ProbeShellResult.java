package com.reajason.javaweb.probe;

import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
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
    private ObfuscationInfo obfuscationInfo;

    public static class Builder {
        public ProbeShellResult build() {
            if (shellBytes != null) {
                shellBytesBase64Str = Base64.getEncoder().encodeToString(shellBytes);
                shellSize = shellBytes.length;
            }
            return new ProbeShellResult(shellClassName, shellBytes, shellSize, shellBytesBase64Str, probeConfig, probeContentConfig, obfuscationInfo);
        }
    }
}
