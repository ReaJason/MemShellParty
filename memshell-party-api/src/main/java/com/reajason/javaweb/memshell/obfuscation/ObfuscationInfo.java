package com.reajason.javaweb.memshell.obfuscation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 字节码混淆结果信息（混淆状态与前后体积）。
 *
 * @author ReaJason
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ObfuscationInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    @Builder.Default
    private boolean enabled = false;

    private long originalShellSize;
    private long obfuscatedShellSize;
    private long originalInjectorSize;
    private long obfuscatedInjectorSize;

    public long getOriginalSize() {
        return originalShellSize + originalInjectorSize;
    }

    public long getObfuscatedSize() {
        return obfuscatedShellSize + obfuscatedInjectorSize;
    }
}
