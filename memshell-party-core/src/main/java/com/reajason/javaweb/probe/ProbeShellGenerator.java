package com.reajason.javaweb.probe;

import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import net.bytebuddy.jar.asm.Opcodes;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class ProbeShellGenerator {

    public static ProbeShellResult generate(ProbeConfig probeConfig, ProbeContentConfig contentConfig) {
        // 入口补齐，同 MemShellGenerator#generate：0 不是合法 class 版本，等同「没传」
        if (probeConfig.getTargetJreVersion() == 0) {
            probeConfig.setTargetJreVersion(Opcodes.V1_6);
        }
        if (StringUtils.isBlank(probeConfig.getShellClassName())) {
            probeConfig.setShellClassName(CommonUtil.generateInjectorClassName());
        }
        if (probeConfig.isLambdaSuffix()) {
            probeConfig.setShellClassName(CommonUtil.appendLambdaSuffix(probeConfig.getShellClassName()));
        }
        byte[] bytes = probeConfig.getProbeMethod().generateBytes(probeConfig, contentConfig);
        return ProbeShellResult.builder()
                .shellClassName(probeConfig.getShellClassName())
                .shellBytes(bytes)
                .probeConfig(probeConfig)
                .probeContentConfig(contentConfig)
                .build();
    }
}
