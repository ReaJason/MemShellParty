package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.probe.ProbeShellResult;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author ReaJason
 * @since 2025/8/10
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProbeShellGenerateResponse {
    private ProbeShellResult probeShellResult;
    private String packResult;
}
