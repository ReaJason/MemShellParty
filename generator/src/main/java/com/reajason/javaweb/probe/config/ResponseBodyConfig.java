package com.reajason.javaweb.probe.config;

import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
@Getter
@SuperBuilder
@ToString
public class ResponseBodyConfig extends ProbeContentConfig {
    private String server;
    private String reqParamName;
    private String reqHeaderName;
}
