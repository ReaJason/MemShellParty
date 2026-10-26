package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
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
@Builder(builderClassName = "Builder")
public class MemShellResult {
    private String shellClassName;
    private transient byte[] shellBytes;
    private long shellSize;
    private String shellBytesBase64Str;
    /**
     * 辅助类（如 RawWebSocket 的 $RawWsHelper、Dubbo 的服务接口）；没有辅助类时全组字段为 null/0
     */
    private String helperClassName;
    private transient byte[] helperBytes;
    private long helperSize;
    private String helperBytesBase64Str;
    private String injectorClassName;
    private transient byte[] injectorBytes;
    private transient Map<String, byte[]> injectorInnerClassBytes;
    private long injectorSize;
    private String injectorBytesBase64Str;
    private ShellConfig shellConfig;
    private ShellToolConfig shellToolConfig;
    private InjectorConfig injectorConfig;
    private ObfuscationInfo obfuscationInfo;

    public static class Builder {
        public MemShellResult build() {
            if (shellBytes != null) {
                shellBytesBase64Str = Base64.getEncoder().encodeToString(shellBytes);
                shellSize = shellBytes.length;
            }
            if (helperBytes != null) {
                helperBytesBase64Str = Base64.getEncoder().encodeToString(helperBytes);
                helperSize = helperBytes.length;
            }
            if (injectorBytes != null) {
                injectorBytesBase64Str = Base64.getEncoder().encodeToString(injectorBytes);
                injectorSize = injectorBytes.length;
            }
            return new MemShellResult(shellClassName, shellBytes, shellSize, shellBytesBase64Str,
                    helperClassName, helperBytes, helperSize, helperBytesBase64Str,
                    injectorClassName, injectorBytes, injectorInnerClassBytes, injectorSize, injectorBytesBase64Str, shellConfig, shellToolConfig, injectorConfig, obfuscationInfo);
        }
    }
}
