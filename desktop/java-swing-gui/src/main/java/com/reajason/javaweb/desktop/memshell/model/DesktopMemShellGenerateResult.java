package com.reajason.javaweb.desktop.memshell.model;

import com.reajason.javaweb.memshell.MemShellResult;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 桌面端生成结果：包装 {@link MemShellResult} 与打包产物。
 * 聚合打包器产生多条目（Map），普通打包器产生单条目（String）。
 */
public class DesktopMemShellGenerateResult {
    private final MemShellResult memShellResult;
    private final String packMethod;
    private final String packResult;
    private final Map<String, String> packResults;

    public DesktopMemShellGenerateResult(MemShellResult memShellResult, String packMethod, String packResult) {
        this.memShellResult = memShellResult;
        this.packMethod = packMethod;
        this.packResult = packResult;
        this.packResults = null;
    }

    public DesktopMemShellGenerateResult(MemShellResult memShellResult, String packMethod, Map<String, String> packResults) {
        this.memShellResult = memShellResult;
        this.packMethod = packMethod;
        this.packResult = null;
        this.packResults = packResults == null ? null : new LinkedHashMap<String, String>(packResults);
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

    public boolean isJarOutput() {
        return !isMultiResult() && packMethod != null && packMethod.endsWith("Jar");
    }

    public boolean isAgentOutput() {
        return packMethod != null && packMethod.startsWith("Agent");
    }

    /**
     * @return 是否为纯 Agent Jar（无内置 Attacher，需配合 jattach 注入，对齐 web agent.tsx isPureAgent）
     */
    public boolean isPureAgentOutput() {
        return "AgentJar".equals(packMethod);
    }
}
