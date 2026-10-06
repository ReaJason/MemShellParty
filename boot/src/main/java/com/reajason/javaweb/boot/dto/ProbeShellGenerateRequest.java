package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.boot.service.ProbeContentConfigMapper;
import com.reajason.javaweb.boot.service.ProbeContentParams;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.config.*;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
public class ProbeShellGenerateRequest {
    private ProbeConfig probeConfig;
    private ProbeContentConfigDTO probeContentConfig;
    private Packers packer;

    @Data
    static class ProbeContentConfigDTO {
        private String host;
        private int seconds;
        private String server;
        private String sleepServer;
        private String reqParamName;
        private String commandTemplate;
    }

    public ProbeContentConfig parseProbeContentConfig() {
        return ProbeContentConfigMapper.map(probeConfig.getProbeMethod(), new ProbeContentParams(
                probeContentConfig.host,
                probeContentConfig.seconds,
                probeContentConfig.server,
                probeContentConfig.sleepServer,
                probeContentConfig.reqParamName,
                probeContentConfig.commandTemplate));
    }
}
