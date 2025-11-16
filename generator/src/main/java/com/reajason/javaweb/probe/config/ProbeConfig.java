package com.reajason.javaweb.probe.config;

import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProbeConfig {
    private ProbeMethod probeMethod;
    private ProbeContent probeContent;

    @Builder.Default
    private String shellClassName = CommonUtil.generateInjectorClassName();
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
     * 是否启用缩小字节码
     */
    @Builder.Default
    private boolean shrink = false;

    /**
     * 是否添加静态代码块调用构造方法
     */
    @Builder.Default
    private boolean staticInitialize = false;

    public boolean isDebugOff() {
        return !debug;
    }

    public boolean needByPassJavaModule() {
        return byPassJavaModule || targetJreVersion >= Opcodes.V9;
    }
}
