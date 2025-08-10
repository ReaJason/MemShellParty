package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.config.*;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
public class ProbeGenerateRequest {
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
        private String reqHeaderName;
    }

    public ProbeContentConfig parseProbeContentConfig() {
        return switch (probeConfig.getProbeMethod()) {
            case DNSLog -> DnsLogConfig.builder()
                    .host(probeContentConfig.host)
                    .build();
            case Sleep -> SleepConfig.builder()
                    .seconds(probeContentConfig.seconds)
                    .server(probeContentConfig.sleepServer)
                    .build();
            case ResponseBody -> ResponseBodyConfig.builder()
                    .reqParamName(probeContentConfig.reqParamName)
                    .reqHeaderName(probeContentConfig.reqHeaderName)
                    .server(probeContentConfig.server)
                    .build();
            default -> throw new UnsupportedOperationException("unknown probe method: " + probeConfig.getProbeMethod());
        };
    }
}
