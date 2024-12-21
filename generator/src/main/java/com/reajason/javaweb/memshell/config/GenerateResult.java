package com.reajason.javaweb.memshell.config;

import lombok.Builder;
import lombok.Data;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Data
@Builder(builderClassName = "GenerateResultBuilder")
public class GenerateResult {
    private String shellClassName;
    private transient byte[] shellBytes;
    private long shellSize;
    private String shellBytesBase64Str;
    private String injectorClassName;
    private transient byte[] injectorBytes;
    private long injectorSize;
    private String injectorBytesBase64Str;
    private ShellConfig shellConfig;
    private ShellToolConfig shellToolConfig;
    private InjectorConfig injectorConfig;

    public static class GenerateResultBuilder {
        public GenerateResult build() {
            if (shellBytes != null) {
                shellBytesBase64Str = Base64.encodeBase64String(shellBytes);
                shellSize = shellBytes.length;
            }
            if (injectorBytes != null) {
                injectorBytesBase64Str = Base64.encodeBase64String(injectorBytes);
                injectorSize = injectorBytes.length;
            }
            return new GenerateResult(shellClassName, shellBytes, shellSize, shellBytesBase64Str,
                    injectorClassName, injectorBytes, injectorSize, injectorBytesBase64Str, shellConfig, shellToolConfig, injectorConfig);
        }
    }
}
