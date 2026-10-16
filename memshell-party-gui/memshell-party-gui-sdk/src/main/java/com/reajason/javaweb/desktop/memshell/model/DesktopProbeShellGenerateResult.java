package com.reajason.javaweb.desktop.memshell.model;

import com.reajason.javaweb.probe.ProbeShellResult;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 桌面端探测马生成结果：包装 {@link ProbeShellResult} 与打包产物。
 * 聚合打包器产生多条目（Map），普通打包器产生单条目（String）。
 * 探测马无注入器，打包目录已排除 Jar/Agent 类产物。
 */
public class DesktopProbeShellGenerateResult {
    private final ProbeShellResult probeShellResult;
    private final String packMethod;
    private final String packResult;
    private final Map<String, String> packResults;

    public DesktopProbeShellGenerateResult(ProbeShellResult probeShellResult, String packMethod, String packResult) {
        this.probeShellResult = probeShellResult;
        this.packMethod = packMethod;
        this.packResult = packResult;
        this.packResults = null;
    }

    public DesktopProbeShellGenerateResult(ProbeShellResult probeShellResult, String packMethod, Map<String, String> packResults) {
        this.probeShellResult = probeShellResult;
        this.packMethod = packMethod;
        this.packResult = null;
        this.packResults = packResults == null ? null : new LinkedHashMap<String, String>(packResults);
    }

    public ProbeShellResult getProbeShellResult() {
        return probeShellResult;
    }

    public String getPackMethod() {
        return packMethod;
    }

    public String getPackResult() {
        return packResult;
    }

    public Map<String, String> getPackResults() {
        return packResults == null ? null : Collections.unmodifiableMap(packResults);
    }

    public boolean isMultiResult() {
        return packResults != null && packResults.size() > 1;
    }

    /**
     * @return 当前默认展示的打包结果（单条目为其本身；聚合取首个条目）
     */
    public String getActivePackResult() {
        if (packResults != null) {
            for (String value : packResults.values()) {
                return value;
            }
            return "";
        }
        return packResult == null ? "" : packResult;
    }
}
