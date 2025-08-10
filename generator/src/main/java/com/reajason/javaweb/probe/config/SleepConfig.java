package com.reajason.javaweb.probe.config;

import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2025/8/1
 */
@Getter
@SuperBuilder
@ToString
public class SleepConfig extends ProbeContentConfig {
    private String server;
    private int seconds;
}
