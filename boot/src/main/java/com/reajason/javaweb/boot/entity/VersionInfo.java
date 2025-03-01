package com.reajason.javaweb.boot.entity;

import lombok.Data;
import lombok.Builder;

/**
 * @author ReaJason
 */
@Data
@Builder
public class VersionInfo {
    private String currentVersion;
    private String latestVersion;
    private boolean hasUpdate;
} 