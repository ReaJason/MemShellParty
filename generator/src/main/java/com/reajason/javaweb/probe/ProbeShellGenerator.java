package com.reajason.javaweb.probe;

import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.utils.CommonUtil;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class ProbeShellGenerator {

    public static ProbeShellResult generate(ProbeConfig probeConfig, ProbeContentConfig contentConfig) {
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
