package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.probe.ProbeShellResult;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
@NoArgsConstructor
public class ProbeShellGenerateResponse {
    private ProbeShellResult probeShellResult;
    private String packResult;
    private Map<String, String> allPackResults;

    public ProbeShellGenerateResponse(ProbeShellResult probeShellResult, String packResult) {
        this.probeShellResult = probeShellResult;
        this.packResult = packResult;
    }

    public ProbeShellGenerateResponse(ProbeShellResult probeShellResult, Map<String, String> allPackResults) {
        this.allPackResults = allPackResults;
        this.probeShellResult = probeShellResult;
    }
}
