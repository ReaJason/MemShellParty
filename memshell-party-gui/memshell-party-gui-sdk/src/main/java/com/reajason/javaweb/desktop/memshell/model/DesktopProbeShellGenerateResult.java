package com.reajason.javaweb.desktop.memshell.model;

import com.reajason.javaweb.probe.ProbeShellResult;

/**
 * 桌面端探测马生成结果：包装 {@link ProbeShellResult} 与打包产物。
 * 探测马无注入器，打包目录已排除 Jar/Agent 类产物。
 */
public class DesktopProbeShellGenerateResult {
    private final ProbeShellResult probeShellResult;
    private final String packMethod;
    private final String packResult;

    public DesktopProbeShellGenerateResult(ProbeShellResult probeShellResult, String packMethod, String packResult) {
        this.probeShellResult = probeShellResult;
        this.packMethod = packMethod;
        this.packResult = packResult;
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
}
