package com.reajason.javaweb.boot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.config.*;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
public class ProbeShellGenerateRequest {
    @JsonPropertyDescription("Probe method/content selection plus generation flags")
    private ProbeConfig probeConfig;

    @JsonPropertyDescription("Probe-method-specific options: host for DNSLog, seconds + sleepServer for Sleep, server + reqParamName for ResponseBody")
    private ProbeContentConfigDTO probeContentConfig;

    @JsonPropertyDescription("Payload packer / output format, e.g. Base64, JSP, ScriptEngine; see memshell_capabilities")
    private Packers packer;

    @Data
    static class ProbeContentConfigDTO {
        @JsonProperty(required = false)
        @JsonPropertyDescription("DNSLog host, e.g. xxx.dnslog.cn; required when probeMethod is DNSLog")
        private String host;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Sleep seconds; used when probeMethod is Sleep")
        private int seconds;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Target server for ResponseBody probe; required when probeMethod is ResponseBody, see probeResponseBodyServers")
        private String server;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Target server for Sleep probe; required when probeMethod is Sleep")
        private String sleepServer;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Request parameter name carrying the echo input / command; random by default")
        private String reqParamName;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command execution template containing a {command} placeholder; optional")
        private String commandTemplate;
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
                    .commandTemplate(probeContentConfig.commandTemplate)
                    .server(probeContentConfig.server)
                    .build();
            default -> throw new UnsupportedOperationException("unknown probe method: " + probeConfig.getProbeMethod());
        };
    }
}
