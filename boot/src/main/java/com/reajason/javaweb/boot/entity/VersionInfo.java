package com.reajason.javaweb.boot.entity;

import lombok.Builder;
import lombok.Data;

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