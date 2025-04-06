package com.reajason.javaweb.memshell.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Base64;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderClassName = "GenerateResultBuilder")
public class GenerateResult {
    private String shellClassName;
    private transient byte[] shellBytes;
    private long shellSize;
    private String shellBytesBase64Str;
    private String injectorClassName;
    private transient byte[] injectorBytes;
    private transient Map<String, byte[]> injectorInnerClassBytes;
    private long injectorSize;
    private String injectorBytesBase64Str;
    private ShellConfig shellConfig;
    private ShellToolConfig shellToolConfig;
    private InjectorConfig injectorConfig;

    public static class GenerateResultBuilder {
        public GenerateResult build() {
            if (shellBytes != null) {
                shellBytesBase64Str = Base64.getEncoder().encodeToString(shellBytes);
                shellSize = shellBytes.length;
            }
            if (injectorBytes != null) {
                injectorBytesBase64Str = Base64.getEncoder().encodeToString(injectorBytes);
                injectorSize = injectorBytes.length;
            }
            return new GenerateResult(shellClassName, shellBytes, shellSize, shellBytesBase64Str,
                    injectorClassName, injectorBytes, injectorInnerClassBytes, injectorSize, injectorBytesBase64Str, shellConfig, shellToolConfig, injectorConfig);
        }
    }
}
