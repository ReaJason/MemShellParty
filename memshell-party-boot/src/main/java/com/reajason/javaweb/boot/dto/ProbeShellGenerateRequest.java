package com.reajason.javaweb.boot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.reajason.javaweb.GenerationException;
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

    @JsonPropertyDescription("Probe-method-specific options: host for DNSLog, seconds + sleepServer for Sleep, server + reqParamName (+ respHeaderName) for ResponseBody/ResponseHeader")
    private ProbeContentConfigDTO probeContentConfig;

    @JsonProperty(required = false)
    @JsonPropertyDescription("Payload packer / output format, e.g. DefaultBase64, JSP, ScriptEngine; see memshell_capabilities. Omit or leave blank for raw Base64 of the probe class.")
    private String packer;

    @Data
    static class ProbeContentConfigDTO {
        @JsonProperty(required = false)
        @JsonPropertyDescription("DNSLog host, e.g. xxx.dnslog.cn; required when probeMethod is DNSLog")
        private String host;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Sleep seconds; used when probeMethod is Sleep")
        private int seconds;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Target server for ResponseBody/ResponseHeader probe; required for those probe methods, see probeResponseServers")
        private String server;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Target server for Sleep probe; required when probeMethod is Sleep")
        private String sleepServer;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Request parameter/header name carrying the echo input, or claiming the live request for Server + Unknown; random by default when used, omitted otherwise")
        private String reqParamName;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Command execution template containing a {command} placeholder; optional")
        private String commandTemplate;

        @JsonProperty(required = false)
        @JsonPropertyDescription("Response header name for ResponseHeader probe, e.g. X-Cmd; random X- prefixed name by default. " +
                "Short header-safe ASCII results are plain text; non-ASCII or long results are Base64 encoded and split across <name>, <name>-2, ...")
        private String respHeaderName;
    }

    /**
     * @throws GenerationException probeConfig / probeMethod / probeContentConfig 缺失时无法猜出要生成什么，
     *                             明确报缺哪个字段，而不是在下面解引用时 NPE
     */
    public ProbeContentConfig parseProbeContentConfig() {
        if (probeConfig == null || probeConfig.getProbeMethod() == null) {
            throw new GenerationException("probeConfig.probeMethod is required: DNSLog, ResponseBody, ResponseHeader or Sleep");
        }
        if (probeContentConfig == null) {
            throw new GenerationException("probeContentConfig is required for probeMethod " + probeConfig.getProbeMethod());
        }
        return switch (probeConfig.getProbeMethod()) {
            case DNSLog -> DnsLogConfig.builder()
                    .host(probeContentConfig.host)
                    .build();
            case Sleep -> SleepConfig.builder()
                    .seconds(probeContentConfig.seconds)
                    .server(probeContentConfig.sleepServer)
                    .build();
            case ResponseBody -> ResponseConfig.builder()
                    .reqParamName(probeContentConfig.reqParamName)
                    .commandTemplate(probeContentConfig.commandTemplate)
                    .server(probeContentConfig.server)
                    .build();
            case ResponseHeader -> ResponseConfig.builder()
                    .reqParamName(probeContentConfig.reqParamName)
                    .commandTemplate(probeContentConfig.commandTemplate)
                    .server(probeContentConfig.server)
                    .respHeaderName(probeContentConfig.respHeaderName)
                    .build();
            default -> throw new UnsupportedOperationException("unknown probe method: " + probeConfig.getProbeMethod());
        };
    }
}
