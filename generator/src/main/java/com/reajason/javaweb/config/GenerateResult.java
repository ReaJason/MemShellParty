package com.reajason.javaweb.config;

import lombok.Builder;
import lombok.Data;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Data
@Builder
public class GenerateResult {
    private String shellClassName;
    private transient byte[] shellBytes;
    private String shellBytesBase64Str;
    private String injectorClassName;
    private transient byte[] injectorBytes;
    private String injectorBytesBase64Str;
    private ShellConfig shellConfig;

    public GenerateResult encodeBase64() {
        this.shellBytesBase64Str = Base64.encodeBase64String(shellBytes);
        this.injectorBytesBase64Str = Base64.encodeBase64String(injectorBytes);
        return this;
    }
}
