package com.reajason.javaweb.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2024/12/6
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ShellConfig {
    /**
     * 目标服务类型
     */
    Server server;

    /**
     * 内存马功能
     */
    ShellTool shellTool;

    /**
     * 内存马类型
     */
    String shellType;

    /**
     * 生成类的目标 JDK 版本
     */
    @Builder.Default
    private int targetJdkVersion = Constants.DEFAULT_VERSION;

    /**
     * 是否开启混淆
     */
    @Builder.Default
    private boolean obfuscate = false;

    /**
     * 是否开启调试
     */
    @Builder.Default
    private boolean debug = false;


    public boolean isJakarta() {
        return StringUtils.containsIgnoreCase(shellType, "jakarta");
    }

    public boolean needByPassJdkModule() {
        return targetJdkVersion >= Opcodes.V9;
    }
}
