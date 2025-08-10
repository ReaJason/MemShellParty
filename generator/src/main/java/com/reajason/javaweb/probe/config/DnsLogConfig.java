package com.reajason.javaweb.probe.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
@Getter
@SuperBuilder
@ToString
public class DnsLogConfig extends ProbeContentConfig {
    private String host;
}
