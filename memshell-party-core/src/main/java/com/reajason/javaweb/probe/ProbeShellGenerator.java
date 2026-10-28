package com.reajason.javaweb.probe;

import com.reajason.javaweb.memshell.obfuscation.ClassObfuscation;
import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo;
import com.reajason.javaweb.memshell.obfuscation.ObfuscationTarget;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;
import net.bytebuddy.jar.asm.Opcodes;

import java.util.Collections;

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
        byte[] bytes = ProbeMethodDispatcher.generateBytes(probeConfig, contentConfig);

        // 混淆时序：生成探测类字节码之后，套用 PROBE_COMMON 契约
        ObfuscationInfo obfuscationInfo = null;
        if (probeConfig.isObfuscationEnabled()) {
            obfuscationInfo = ObfuscationInfo.builder().enabled(true).build();
            obfuscationInfo.setOriginalShellSize(bytes.length);
            bytes = ClassObfuscation.obfuscate(
                    bytes, probeConfig.getShellClassName(), probeConfig.getTargetJreVersion(),
                    ObfuscationTarget.PROBE, probeConfig.getObfuscation(),
                    MethodContracts.PROBE_COMMON, Collections.<String, byte[]>emptyMap(), false);
            obfuscationInfo.setObfuscatedShellSize(bytes.length);
        }

        return ProbeShellResult.builder()
                .shellClassName(probeConfig.getShellClassName())
                .shellBytes(bytes)
                .probeConfig(probeConfig)
                .probeContentConfig(contentConfig)
                .obfuscationInfo(obfuscationInfo)
                .build();
    }
}
