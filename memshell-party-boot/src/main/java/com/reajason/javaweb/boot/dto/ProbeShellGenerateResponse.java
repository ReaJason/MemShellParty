package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.probe.ProbeShellResult;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
@NoArgsConstructor
public class ProbeShellGenerateResponse {
    private ProbeShellResult probeShellResult;
    private String packResult;

    public ProbeShellGenerateResponse(ProbeShellResult probeShellResult, String packResult) {
        this.probeShellResult = probeShellResult;
        this.packResult = packResult;
    }
}
