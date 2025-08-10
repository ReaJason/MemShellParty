package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.probe.ProbeResult;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
@NoArgsConstructor
public class ProbeGenerateResponse {
    private ProbeResult probeResult;
    private String packResult;
    private Map<String, String> allPackResults;

    public ProbeGenerateResponse(ProbeResult probeResult, String packResult) {
        this.probeResult = probeResult;
        this.packResult = packResult;
    }

    public ProbeGenerateResponse(ProbeResult probeResult, Map<String, String> allPackResults) {
        this.allPackResults = allPackResults;
        this.probeResult = probeResult;
    }
}
