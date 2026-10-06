package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.DnsLogConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.config.SleepConfig;

/**
 * 按 probeMethod 把扁平参数映射为对应的 {@link ProbeContentConfig}。
 * <p>
 * REST 与 MCP 两个入口共用此映射，避免各自维护一份 switch 而漂移。
 *
 * @author ReaJason
 */
public final class ProbeContentConfigMapper {

    private ProbeContentConfigMapper() {
    }

    public static ProbeContentConfig map(ProbeMethod probeMethod, ProbeContentParams params) {
        return switch (probeMethod) {
            case DNSLog -> DnsLogConfig.builder()
                    .host(params.host())
                    .build();
            case Sleep -> SleepConfig.builder()
                    .seconds(params.seconds())
                    .server(params.sleepServer())
                    .build();
            case ResponseBody -> ResponseBodyConfig.builder()
                    .reqParamName(params.reqParamName())
                    .commandTemplate(params.commandTemplate())
                    .server(params.server())
                    .build();
        };
    }
}
