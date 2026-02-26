package com.reajason.javaweb.desktop.memshell.model;

import com.reajason.javaweb.memshell.MemShellResult;

public class DesktopMemShellGenerateResult {
    private final MemShellResult memShellResult;
    private final String packMethod;
    private final String packResult;
    private final boolean jarOutput;
    private final boolean agentOutput;

    public DesktopMemShellGenerateResult(MemShellResult memShellResult, String packMethod, String packResult) {
        this.memShellResult = memShellResult;
        this.packMethod = packMethod;
        this.packResult = packResult;
        this.jarOutput = packMethod != null && packMethod.endsWith("Jar");
        this.agentOutput = packMethod != null && packMethod.startsWith("Agent");
    }

    public MemShellResult getMemShellResult() { return memShellResult; }
    public String getPackMethod() { return packMethod; }
    public String getPackResult() { return packResult; }
    public boolean isJarOutput() { return jarOutput; }
    public boolean isAgentOutput() { return agentOutput; }
}
