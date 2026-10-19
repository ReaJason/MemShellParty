package com.reajason.javaweb.memshell.obfuscation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 字节码混淆结果信息（混淆状态、前后体积与 Header 载荷预警）。
 *
 * @author ReaJason
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ObfuscationInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 经 HTTP Header 传输的载荷（如 Shiro Cookie）体积预警阈值：超过 4KB 易触发 400 Bad Request
     */
    public static final int HEADER_PAYLOAD_WARNING_THRESHOLD = 4096;

    @Builder.Default
    private boolean enabled = false;

    private long originalShellSize;
    private long obfuscatedShellSize;
    private long originalInjectorSize;
    private long obfuscatedInjectorSize;

    /**
     * 打包后载荷长度；仅当 Packer 声明经 HTTP Header 传输时由 pack 层回填。
     */
    private Long packedPayloadSize;

    /**
     * 打包后载荷是否超过 {@link #HEADER_PAYLOAD_WARNING_THRESHOLD}。
     */
    private boolean headerPayloadTooLarge;

    public long getOriginalSize() {
        return originalShellSize + originalInjectorSize;
    }

    public long getObfuscatedSize() {
        return obfuscatedShellSize + obfuscatedInjectorSize;
    }

    /**
     * pack 层回填最终载荷体积，并据此判断 Header 传输是否超限。
     */
    public void recordPackedPayloadSize(long size) {
        this.packedPayloadSize = size;
        this.headerPayloadTooLarge = size > HEADER_PAYLOAD_WARNING_THRESHOLD;
    }
}
