package com.reajason.javaweb.desktop.memshell.model;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.Packers;

/**
 * 桌面端生成结果：包装 {@link MemShellResult} 与打包产物。
 */
public class DesktopMemShellGenerateResult {
    private final MemShellResult memShellResult;
    private final String packMethod;
    private final String packResult;

    public DesktopMemShellGenerateResult(MemShellResult memShellResult, String packMethod, String packResult) {
        this.memShellResult = memShellResult;
        this.packMethod = packMethod;
        this.packResult = packResult;
    }

    public MemShellResult getMemShellResult() {
        return memShellResult;
    }

    public String getPackMethod() {
        return packMethod;
    }

    public String getPackResult() {
        return packResult;
    }

    public boolean isJarOutput() {
        return packMethod != null && packMethod.endsWith(Packers.Jar);
    }

    public boolean isAgentOutput() {
        return packMethod != null && packMethod.startsWith("Agent");
    }

    /**
     * @return 是否为纯 Agent Jar（无内置 Attacher，需配合 jattach 注入，对齐 web agent.tsx isPureAgent）
     */
    public boolean isPureAgentOutput() {
        return Packers.AgentJar.equals(packMethod);
    }
}
