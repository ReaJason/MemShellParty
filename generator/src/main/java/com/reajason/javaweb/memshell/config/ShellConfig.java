package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.ShellType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.bytebuddy.jar.asm.Opcodes;

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
    private String server;

    /**
     * 目标服务版本
     */
    @Builder.Default
    private String serverVersion = "unknown";

    /**
     * 内存马功能
     */
    private String shellTool;

    /**
     * 内存马类型
     */
    private String shellType;

    /**
     * 生成类的目标 JRE 版本
     */
    @Builder.Default
    private int targetJreVersion = Opcodes.V1_6;

    /**
     * 是否需要移除模块限制
     */
    @Builder.Default
    private boolean byPassJavaModule = false;

    /**
     * 是否开启调试
     */
    @Builder.Default
    private boolean debug = false;

    /**
     * 是否使用回显模式
     */
    @Builder.Default
    private boolean probe = false;

    /**
     * 是否启用缩小字节码
     */
    @Builder.Default
    private boolean shrink = false;

    /**
     * 追加 Lambda 类名后缀
     */
    @Builder.Default
    private boolean lambdaSuffix = false;

    /**
     * 将 Java EE 转换为 Jakarta EE 类名
     */
    @Builder.Default
    private boolean jakarta = false;

    public boolean isDebugOff() {
        return !debug;
    }

    public boolean isJakarta() {
        return jakarta || shellType.startsWith(ShellType.JAKARTA);
    }

    public boolean needByPassJavaModule() {
        return byPassJavaModule || targetJreVersion >= Opcodes.V9;
    }
}
