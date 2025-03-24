package com.reajason.javaweb.boot.entity;

import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@Data
public class Config {
    private Map<String, List<String>> servers;
    private Map<String, Map<?, ?>> core;
    private List<String> packers;
}