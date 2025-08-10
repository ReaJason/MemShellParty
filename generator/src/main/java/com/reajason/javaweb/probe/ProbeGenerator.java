package com.reajason.javaweb.probe;

import com.reajason.javaweb.memshell.utils.CommonUtil;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2025/6/29
 */
public class ProbeGenerator {

    public static ProbeResult generate(ProbeConfig probeConfig, ProbeContentConfig contentConfig) {
        if (StringUtils.isBlank(probeConfig.getShellClassName())) {
            probeConfig.setShellClassName(CommonUtil.generateInjectorClassName());
        }
        byte[] bytes = probeConfig.getProbeMethod().generateBytes(probeConfig, contentConfig);
        return ProbeResult.builder()
                .shellClassName(probeConfig.getShellClassName())
                .shellBytes(bytes)
                .probeConfig(probeConfig)
                .probeContentConfig(contentConfig)
                .build();
    }
}
